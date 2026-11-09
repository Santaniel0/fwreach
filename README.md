# fwreach

fwreach берёт снимок правил netfilter Linux-хоста (iptables и nftables), список
слушающих сокетов и контейнеров Docker и прогоняет через правила входящий пакет
для каждого открытого порта. На выходе таблица: что netfilter этого хоста
пропускает, от каких адресов и куда пакет в итоге попадает. Если что-то из этого
не совпадает с ожиданиями, fwreach показывает, почему так вышло. Пакеты в сеть
утилита не отправляет: всё считается по снимку, и анализ можно запускать на
любой машине.

## Какую проблему решает

Типичная ситуация: VPS на Ubuntu, на нём через Docker Compose крутятся бот и
Postgres. Включён ufw с политикой `deny incoming`, для надёжности добавлено
`ufw deny 5432/tcp`. `ufw status` показывает, что 5432 закрыт. При этом база
доступна из интернета.

Причина в том, что опубликованные порты Docker пропускает через DNAT в цепочке
`nat PREROUTING`. После DNAT адрес назначения становится адресом контейнера, и
пакет идёт по хуку `forward`, а не `input`. Правила ufw стоят в `INPUT` и этот
пакет вообще не видят, а цепочка `DOCKER` его принимает. Docker пишет об этом
прямо: Docker и ufw несовместимы, трафик к опубликованным портам уходит мимо
правил ufw
([документация](https://docs.docker.com/engine/network/packet-filtering-firewalls/)).

На этом обжигаются регулярно. В 2021 году у NewsBlur был включён ufw, а Docker
открыл MongoDB на весь интернет. Через несколько часов автоматический скрипт
удалил базу и оставил требование выкупа
([The Register](https://www.theregister.com/2021/06/29/newsblur_docker_ransomware/)).
Issue [moby/moby#22054](https://github.com/moby/moby/issues/22054) открыт с 2016
года.

С nftables путаницы не меньше. В Docker 29 появился бэкенд nftables, и Docker
пишет, что в будущем он станет бэкендом по умолчанию. На одном хуке теперь
работают базовые цепочки из нескольких таблиц, по порядку приоритетов. `accept`
завершает только свою цепочку, а `drop` окончательный. Правило
`tcp dport 3000 drop` в своей цепочке `forward` не срабатывает, потому что
после DNAT у пакета уже порт контейнера
([пример с форума Docker](https://forums.docker.com/t/how-to-block-ports-inusing-nftables-with-docker-v29/151450)).

Обычно это проверяют через nmap с другой машины. Такая проверка показывает одну
точку обзора в один момент и не объясняет, какое правило виновато. fwreach
отвечает на два вопроса: какие порты пропускает netfilter этого хоста и через
какие правила прошёл пакет. С файлом ожиданий он возвращает ненулевой код
выхода, его можно запускать в cron или в CI после деплоя.

## Установка

Нужен Go 1.27 или новее.

```sh
go install github.com/Santaniel0/fwreach/cmd/fwreach@latest
```

Или из исходников:

```sh
git clone https://github.com/Santaniel0/fwreach
cd fwreach
go build -o fwreach ./cmd/fwreach
```

## Снимок хоста

Снимок это каталог с выводом стандартных команд. Его снимают на сервере под
root, а анализируют где угодно. Обязателен хотя бы один файл с правилами,
остальные файлы необязательны.

```sh
mkdir snap && cd snap
sudo iptables-save          > iptables-save.txt
sudo ip6tables-save         > ip6tables-save.txt
sudo iptables-legacy-save   > iptables-legacy-save.txt   # если есть legacy-таблицы
sudo nft -j list ruleset    > nft.json
sudo ss -Hlntup             > ss.txt
ip -j addr                  > ip-addr.json
docker inspect $(docker ps -q) > docker-inspect.json
```

Файл `manifest.json` (`{"host": "...", "collected_at": "..."}`) тоже
необязательный: из него берутся имя хоста и время снимка для отчёта.

Если `iptables-save` работает через бэкенд nf_tables, те же таблицы есть и в
`nft.json`, но там xt-выражения сведены к одному имени. В таком случае таблицы
`filter`/`nat`/`raw`/`mangle`/`security` семейств ip/ip6 fwreach берёт из
`iptables-save`, а из `nft.json` берёт только нативные таблицы.

## Пример

В `testdata/snapshots` лежат синтетические снимки (откуда взяты правила, описано
в `testdata/README.md`). Ниже настоящий вывод fwreach на снимке хоста с ufw и
Docker. В файле ожиданий `testdata/expect.conf` разрешены 22, 80 и 443 отовсюду
и 9100 только из 10.0.0.0/8:

```
$ fwreach analyze -expect testdata/expect.conf testdata/snapshots/ubuntu-ufw-docker
fwreach: what this host's netfilter allows inbound (simulated from a snapshot, no packets sent)
host        web-1, collected 2026-11-09T10:12:03Z
rules       iptables-save.txt: iptables-nft, 3 tables, 99 rules
interfaces  eth0 203.0.113.10
coverage    2 of 99 rules use matches or targets fwreach does not model; 0 findings depend on them

PORT      FAMILY  STATUS               ALLOWED FROM         DELIVERED TO
tcp/22    ipv4    exposed, expected    any via eth0         sshd on 0.0.0.0
tcp/80    ipv4    exposed, expected    any via eth0         container app-web-1 172.18.0.2:80
tcp/443   ipv4    exposed, expected    any via eth0         container app-web-1 172.18.0.2:443
tcp/5432  ipv4    EXPOSED, UNEXPECTED  any via eth0         container app-db-1 172.18.0.3:5432
tcp/6379  ipv4    filtered             -                    (listening: docker-proxy on 127.0.0.1)
tcp/9100  ipv4    exposed, expected    10.0.0.0/8 via eth0  node_exporter on *

tcp/5432 ipv4 from 198.51.100.7 on eth0: delivered to container app-db-1 172.18.0.3:5432
  prerouting  ip nat PREROUTING #1  -m addrtype --dst-type LOCAL -j DOCKER
  prerouting  ip nat DOCKER #3  ! -i br-5c1e9a3f0b2d -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.18.0.3:5432
  routing     172.18.0.3 is on br-5c1e9a3f0b2d: forward
  forward     ip filter FORWARD #1  -j DOCKER-USER
  forward     ip filter FORWARD #2  -j DOCKER-FORWARD
  forward     ip filter DOCKER-FORWARD #1  -j DOCKER-CT
  forward     ip filter DOCKER-FORWARD #2  -j DOCKER-INTERNAL
  forward     ip filter DOCKER-FORWARD #3  -j DOCKER-BRIDGE
  forward     ip filter DOCKER-BRIDGE #2  -o br-5c1e9a3f0b2d -j DOCKER
  forward     ip filter DOCKER #3  -d 172.18.0.3/32 ! -i br-5c1e9a3f0b2d -o br-5c1e9a3f0b2d -p tcp -m tcp --dport 5432 -j ACCEPT
  note        ip filter ufw-user-input #4 "-p tcp -m tcp --dport 5432 -j DROP" would drop this packet on the input path, but DNAT sent it to forward, so input rules never see it
  fix         iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 5432 -j DROP
              see https://docs.docker.com/engine/network/firewall-iptables/#match-the-original-ip-and-ports-for-requests
  fix         if only this host needs it, publish on loopback: -p 127.0.0.1:5432:5432 (compose: "127.0.0.1:5432:5432")
              see https://docs.docker.com/engine/network/port-publishing/

1 unexpected exposure(s)
$ echo $?
1
```

Снимок `ubuntu-ufw-docker-fixed` отличается от этого одним правилом: тем, что
fwreach предложил в первой строке `fix`. После него 5432 становится `filtered`,
а код выхода 0.

Пример для Docker 29 с бэкендом nftables. Здесь в `inet filter` у хука `input`
политика drop, а в цепочке `forward` пользователь добавил `tcp dport 3000 drop`:

```
$ fwreach analyze -expect testdata/expect.conf testdata/snapshots/debian-nft-docker29
...
tcp/3000  ipv4    EXPOSED, UNEXPECTED  any via eth0  container ai-webui-1 172.19.0.2:8080
tcp/3000  ipv6    filtered             -             (listening: docker-proxy on 0.0.0.0, docker-proxy on ::)

tcp/3000 ipv4 from 198.51.100.7 on eth0: delivered to container ai-webui-1 172.19.0.2:8080
  prerouting  ip docker-bridges raw-PREROUTING  policy accept
  prerouting  ip docker-bridges nat-PREROUTING #1  fib daddr type local counter jump nat-prerouting-and-output
  prerouting  ip docker-bridges nat-prerouting-and-output #1  iifname != "br-7d2c41f0e9a8" tcp dport 3000 counter dnat to 172.19.0.2:8080 comment "DNAT"
  routing     172.19.0.2 is on br-7d2c41f0e9a8: forward
  forward     inet filter forward  policy accept
  forward     ip docker-bridges filter-FORWARD #1  oifname vmap @filter-forward-in-jumps ("br-7d2c41f0e9a8" : jump filter-forward-in__br-7d2c41f0e9a8)
  forward     ip docker-bridges filter-forward-in__br-7d2c41f0e9a8 #3  ip daddr 172.19.0.2 tcp dport 8080 counter accept
  note        the policy drop of inet filter input would drop this packet on the input path, but DNAT sent it to forward, so input rules never see it
  note        inet filter forward #1 "tcp dport 3000 drop" matches port 3000, but DNAT already rewrote the packet to 172.19.0.2:8080; match the published port through conntrack (iptables: -m conntrack --ctorigdstport 3000, nft: ct original proto-dst 3000)
  fix         table inet fwreach-guard {
              	chain forward {
              		type filter hook forward priority filter; policy accept;
              		iifname "eth0" meta l4proto tcp ct original proto-dst 3000 drop
              	}
              }
              see https://docs.docker.com/engine/network/firewall-nftables/
```

Путь одного пакета можно посмотреть командой `explain`:

```
$ fwreach explain -port tcp/9100 testdata/snapshots/ubuntu-ufw-docker
tcp/9100 from 198.51.100.7 to 203.0.113.10 on eth0: 1 outcome(s)

#1 drop
  prerouting  ip nat PREROUTING #1  -m addrtype --dst-type LOCAL -j DOCKER
  routing     203.0.113.10 is a local address: input
  input       ip filter INPUT #1  -j ufw-before-logging-input
  input       ip filter INPUT #2  -j ufw-before-input
  input       ip filter ufw-before-input #10  -j ufw-not-local
  input       ip filter ufw-not-local #1  -m addrtype --dst-type LOCAL -j RETURN
  input       ip filter ufw-before-input #13  -j ufw-user-input
  input       ip filter INPUT #3  -j ufw-after-input
  input       ip filter INPUT #4  -j ufw-after-logging-input
  input       ip filter INPUT #5  -j ufw-reject-input
  input       ip filter INPUT #6  -j ufw-track-input
  input       ip filter INPUT  policy drop
```

## Команды и файл ожиданий

```
fwreach analyze [-format text|json] [-expect FILE] [-iface NAME]... [-fail-on-possible] [-v] [-workers N] SNAPSHOT_DIR
fwreach explain -port tcp/5432 [-from ADDR] [-iface NAME] [-to ADDR] SNAPSHOT_DIR
```

Коды выхода: 0 означает, что всё в порядке; 1 означает, что есть порт, который
netfilter пропускает вопреки файлу ожиданий; 2 означает ошибку ввода. С флагом
`-v` трасса выводится для каждой строки, а в конце печатается список правил,
которые fwreach не умеет вычислять.

Файл ожиданий перечисляет то, что открыто намеренно:

```
allow tcp/22      from any
allow tcp/80,443  from any
allow tcp/9100    from 10.0.0.0/8, 192.168.0.0/16
```

Каждая строка разрешает порт для указанных источников. Если источник может
достучаться до порта, но ни одна строка этого не разрешает, это нарушение.

## Как это работает

Оба формата сначала переводятся в общее промежуточное представление. Это
таблицы с базовыми цепочками (хук, тип, приоритет, политика) и правилами вида
«список условий плюс действие». Вывод `iptables-save` разбирается построчно,
встроенным цепочкам проставляются приоритеты, с которыми их регистрирует ядро
(raw −300, mangle −150, nat −100 на prerouting, filter 0, security 50). Для `nft -j list
ruleset` каждое выражение раскладывается в конкретную структуру. Именованные
множества подставляются сразу, а verdict map превращается в последовательность
правил, по одному на элемент. Ключи в map не пересекаются, поэтому результат
тот же.

Симулятор ведёт пакет так же, как ядро. Сначала хук `prerouting`, где все
базовые цепочки всех источников идут по возрастанию приоритета. `accept`
завершает только текущую цепочку, `drop` и `reject` окончательные. Из
NAT-цепочек хука срабатывает первая, которая сделала DNAT, остальные NAT-цепочки
этого хука пропускаются. Дальше решение о маршруте: если адрес назначения после
DNAT принадлежит хосту, пакет идёт в `input`, если он в подсети моста, то в
`forward` с этим мостом как выходным интерфейсом. Правила, которые fwreach не
вычисляет (`-m recent`, `limit`, xt-выражения без параметров), он не угадывает.
Симуляция раздваивается на «совпало» и «не совпало», а в отчёте такой порт
получает статус `possible` и ссылку на конкретное правило. Число развилок
ограничено.

Источник не обязательно перебирать по адресам. Каждый префикс из правил и из
файла ожиданий режет адресное пространство на отрезки, и внутри отрезка все
правила отвечают одинаково. Поэтому достаточно одного представителя на
отрезок. Для «остального интернета» берётся документационный адрес
198.51.100.7 или 2001:db8:ffff::7. Отрезки с одинаковым результатом
склеиваются обратно в минимальный список CIDR. Прогоны независимы, их
выполняет ограниченный пул воркеров с отменой через context. Результаты
складываются по индексу задания, так что вывод не зависит от расписания.

У каждой подсказки `fix` есть ссылка на документацию Docker, на которой она
основана. Прежде чем напечатать подсказку, fwreach добавляет предложенное
правило в загруженный набор и прогоняет тот же пакет ещё раз. Если пакет
по-прежнему проходит, подсказка не печатается. Подсказку про публикацию на
127.0.0.1 так не проверить, потому что правила генерирует сам Docker. Её
проверяют тесты: на правилах, которые Docker генерирует для такой публикации
(взяты из документации moby).

## Ограничения

- Снимки в `testdata` синтетические. Правила взяты из сгенерированной
  документации moby и из файлов ufw, а JSON для nftables переписан вручную по
  схеме libnftables-json(5). Команды снятия снимка и разбор их вывода ни разу
  не проверялись на настоящем хосте. Отдельной команды `collect` нет: файлы
  снимаются вручную командами выше.
- Моделируется только первый пакет TCP/UDP-соединения (conntrack NEW) на хуках
  prerouting, input и forward. Не моделируются: policy routing, TPROXY, IPVS
  (kube-proxy, Docker Swarm), br_netfilter, хуки ingress и postrouting,
  содержимое ipset, исходящий трафик, ICMP.
- Правила с `limit`, `recent`, `set`, xt-выражениями и прочими неизвестными
  модулями дают `possible`, а не точный ответ. Например, `ufw limit 22/tcp`
  оставит порт 22 в статусе `possible`.
- Из nftables поддержано подмножество выражений: адреса, порты, интерфейсы,
  `meta l4proto/nfproto/mark`, `ct state/status/original`, `fib ... type`,
  множества, verdict map, dnat/redirect, `meta mark set`. Остальное считается
  неизвестным. Отдельно firewalld не проверялся: его таблицы разбираются как
  любые другие, насколько хватает подмножества.
- Сокет на `[::]` считается двухстековым (Linux по умолчанию,
  `net.ipv6.bindv6only=0`). На каждом внешнем интерфейсе проверяется один адрес
  каждого семейства. Интерфейсы определяются эвристикой (не loopback, не
  `docker0`/`br-*`), а точно их можно задать флагом `-iface`.
- Отчёт описывает только netfilter этого хоста. Облачные security groups и
  файрволы перед хостом в снимок не попадают.
- Похожая утилита для чистого iptables уже есть:
  [c0m4r/iptables-analyzer](https://github.com/c0m4r/iptables-analyzer). Нативный
  nftables и смешанные конфигурации она не разбирает, а fwreach разбирает.

## Разработка

```sh
go vet ./...
go test -race ./...
go test ./cmd/fwreach -update   # перезаписать golden-файлы отчёта
```

## Лицензия

MIT, см. `LICENSE`. Происхождение и лицензии материалов в `testdata` описаны
в `testdata/README.md`.
