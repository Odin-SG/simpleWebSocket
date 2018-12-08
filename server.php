<?php 
if($argv[1] == 'deamon' || $_REQUEST['command'] == 'deamon'){
	WebSock::upWebSocket();
}

class WebSock {  
    protected static $sock = null;
    protected static $connects = null;
    
    public static function upWebSocket(){
        self::$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_set_option(self::$sock, SOL_SOCKET, SO_REUSEADDR, 1);
        self::$connects = array(self::$sock);
        self::startHandler();
    }
    public static function startHandler(){
        try{
            if(!socket_bind(self::$sock, '127.0.0.1', '1112')){
                throw new Exception(socket_strerror(socket_last_error(self::$sock)), socket_last_error(self::$sock));
            }
            if(!socket_listen(self::$sock, 1)){
                throw new Exception(socket_strerror(socket_last_error(self::$sock)), socket_last_error(self::$sock));
            }
            while(true){
                $read = $write = self::$connects;
                $changes = socket_select($read, $write, $except = null, 0);
                if($changes === false){
                    throw new Exception(socket_strerror(socket_last_error(self::$sock)), socket_last_error(self::$sock));
                } elseif($changes > 0){
                    if(in_array(self::$sock, $read)){
                        self::$connects[] = $connect = socket_accept(self::$sock);
                        $ip = '';
                        socket_getpeername($connect, $ip);
                        if($connect === false){
                            throw new Exception(socket_strerror(socket_last_error(self::$sock)), socket_last_error(self::$sock));
                        }
                        $key = array_search(self::$sock, $read);
                        unset($read[$key]);
                    }
                    foreach ($read as $read_sock){
                        $data = @socket_read($read_sock, 1024);
                        if ($data === false) {
                            $key = array_search($read_sock, self::$connects);
                            socket_shutdown(self::$connects[$key]);
                            unset(self::$connects[$key]);
                            continue;
                        }
                        $data = trim($data);
                        if (!empty($data)) {
                            if($parsedHeaders = self::parseHeaders($data)){
                                $hendshakeHeaders = self::handshake($parsedHeaders);
                                socket_write($read_sock, $hendshakeHeaders);
                            }
                            $decData = self::decode($data);
                            if(!empty($decData['payload']) && !empty($decData['type'])){
                                if($decData['type'] != 'close'){
                                    foreach ($write as $conn){
                                        if($conn != self::$sock && $conn != $read_sock){
                                            if(!socket_write($conn, self::encode( $decData['payload']))){
                                                $key = array_search($conn, self::$connects);
                                                unset(self::$connects[$key]);
                                                //Ќадо очистить все массивы от битой сессии
                                            }
                                        }
                                    }
                                } else {
                                    $key = array_search($read_sock, self::$connects);
                                    unset(self::$connects[$key]);
                                }
                            }
                        }
                    }
                }
                
            }
            socket_shutdown(self::$sock);
        } catch (Exception $e){
            socket_shutdown(self::$sock);
        }
    }
    
    protected static function parseHeaders($data){
        $regHeaders = '/(\S*):\s(.*\S)/';
        $info = $mathes = array();
        if(preg_match_all ($regHeaders, $data, $mathes, PREG_SET_ORDER)){
            foreach ($mathes as $group){
                $info[$group[1]] = trim($group[2]);
            }
            return $info;
        }
        return false;
    }
    
    protected static function handshake($headers){
        $reply = '';
        if($headers['Upgrade'] == 'websocket'){
            $SecWebSocketAccept = base64_encode(pack('H*', sha1($headers['Sec-WebSocket-Key'].'258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
            $reply = "HTTP/1.1 101 Switching Protocols\r\n".
                     "Upgrade: websocket\r\n".
                     "Connection: Upgrade\r\n".
                     "Sec-WebSocket-Accept: {$SecWebSocketAccept}\r\n";
            $reply .= "\r\n";
        }
        return $reply;
    }
    
    protected static function decode($data){
        $unmaskedPayload = '';
        $decodedData = array();
    
        $firstByteBinary = sprintf('%08b', ord($data[0]));
        $secondByteBinary = sprintf('%08b', ord($data[1]));
        $opcode = bindec(substr($firstByteBinary, 4, 4));
        $isMasked = ($secondByteBinary[0] == '1') ? true : false;
        $payloadLength = ord($data[1]) & 127;
        
        if (!$isMasked) {
            return array('type' => '', 'payload' => '', 'error' => 'protocol error (1002)');
        }
        
        switch ($opcode) {
            case 1:
                $decodedData['type'] = 'text';
                break;
                
            case 2:
                $decodedData['type'] = 'binary';
                break;
    
            case 8:
                $decodedData['type'] = 'close';
                break;
    
            case 9:
                $decodedData['type'] = 'ping';
                break;
    
            case 10:
                $decodedData['type'] = 'pong';
                break;
                
            default:
                return array('type' => '', 'payload' => '', 'error' => 'unknown opcode (1003)');
        }
        
        if ($payloadLength === 126) {
            $mask = substr($data, 4, 4);
            $payloadOffset = 8;
            $dataLength = bindec(sprintf('%08b', ord($data[2])) . sprintf('%08b', ord($data[3]))) + $payloadOffset;
        } elseif ($payloadLength === 127) {
            $mask = substr($data, 10, 4);
            $payloadOffset = 14;
            $tmp = '';
            for ($i = 0; $i < 8; $i++) {
                $tmp .= sprintf('%08b', ord($data[$i + 2]));
            }
            $dataLength = bindec($tmp) + $payloadOffset;
            unset($tmp);
        } else {
            $mask = substr($data, 2, 4);
            $payloadOffset = 6;
            $dataLength = $payloadLength + $payloadOffset;
        }
    
        if (strlen($data) < $dataLength) {
            return false;
        }
        
        if ($isMasked) {
            for ($i = $payloadOffset; $i < $dataLength; $i++) {
                $j = $i - $payloadOffset;
                if (isset($data[$i])) {
                    $unmaskedPayload .= $data[$i] ^ $mask[$j % 4];
                }
            }
            $decodedData['payload'] = $unmaskedPayload;
        } else {
            $payloadOffset = $payloadOffset - 4;
            $decodedData['payload'] = substr($data, $payloadOffset);
        }
        
        return $decodedData;
    }
    
    protected static function encode($payload, $type = 'text', $masked = false){
        $frameHead = array();
        $payloadLength = strlen($payload);
        
        switch ($type) {
            case 'text':
                $frameHead[0] = 129;
                break;
                
            case 'close':
                $frameHead[0] = 136;
                break;
                
            case 'ping':
                $frameHead[0] = 137;
                break;
                
            case 'pong':
                $frameHead[0] = 138;
                break;
        }
    
        if ($payloadLength > 65535) {
            $payloadLengthBin = str_split(sprintf('%064b', $payloadLength), 8);
            $frameHead[1] = ($masked === true) ? 255 : 127;
            for ($i = 0; $i < 8; $i++) {
                $frameHead[$i + 2] = bindec($payloadLengthBin[$i]);
            }
            if ($frameHead[2] > 127) {
                return array('type' => '', 'payload' => '', 'error' => 'frame too large (1004)');
            }
        } elseif ($payloadLength > 125) {
            $payloadLengthBin = str_split(sprintf('%016b', $payloadLength), 8);
            $frameHead[1] = ($masked === true) ? 254 : 126;
            $frameHead[2] = bindec($payloadLengthBin[0]);
            $frameHead[3] = bindec($payloadLengthBin[1]);
        } else {
            $frameHead[1] = ($masked === true) ? $payloadLength + 128 : $payloadLength;
        }
    
        foreach (array_keys($frameHead) as $i) {
            $frameHead[$i] = chr($frameHead[$i]);
        }
        if ($masked === true) {
            $mask = array();
            for ($i = 0; $i < 4; $i++) {
                $mask[$i] = chr(rand(0, 255));
            }
            
            $frameHead = array_merge($frameHead, $mask);
        }
        $frame = implode('', $frameHead);
    
        for ($i = 0; $i < $payloadLength; $i++) {
            $frame .= ($masked === true) ? $payload[$i] ^ $mask[$i % 4] : $payload[$i];
        }
        
        return $frame;
    }
}
    
?>