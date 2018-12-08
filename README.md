# simpleWebSocket
Простой класс сервера вебсокета на php
Запуск демона
  linux: nohup php -f [путь к файлу] deamon > /dev/null 2>&1 & echo $!
  windows: start /B cmd /C "php [путь к файлу] daemon >NUL 2>NUL

Подключение:
1. В браузере в консоли на нескольких вкладках подключитесь к серверу:
var sock = new WebSocket('ws://127.0.0.1:1112');
sock.onmessage = function (mes) { alert(mes.data); }

2. Отправьте сообщение с одной из вкладок
sock.send('Hello world!');
Сообщение отправится на все соединения
