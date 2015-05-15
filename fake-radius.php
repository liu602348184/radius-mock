#!/usr/bin/php -q
<?php
/**
 * Author: Jorge Pereira <jorge.pereira@mobicare.com.br>
 * Seguindo a rfc https://tools.ietf.org/html/rfc5176

  

/* config set */
$port = 1812;
$qtd = 1;

/* debug options */
error_reporting(E_ALL);

/* Allow the script to hang around waiting for connections. */
set_time_limit(0);

/* Turn on implicit output flushing so we see what we're getting
 * as it comes in. */
ob_implicit_flush();

/* handlers */
function cb_coa_request($payload, $client_ip, $client_port) {
  echo "STUB: cb_coa_request()\n";
  return true;
}

function cb_access_request($payload, $client_ip, $client_port) {
  echo "STUB: cb_access_request()\n";
  return true;
}

/* codes and handlers */
$code_map = array( /* Codes: Radius-Auth, rfc https://tools.ietf.org/html/rfc2865 */
                   1 => array("Access-Request",     "cb_access_request"),
                   2 => array("Access-Accept",      null ),
                   3 => array("Access-Reject",      null ),
                   4 => array("Accounting-Request", null ),
                   5 => array("Accounting-Response",null ),
                  11 => array("Access-Challenge",   null ),

                  /* Codes: CoA rfc https://tools.ietf.org/html/rfc5176 */
                  40 => array("Disconnect-Request", null ),
                  41 => array("Disconnect-ACK",     null ),
                  42 => array("Disconnect-NAK",     null ),
                  43 => array("CoA-Request",        "cb_coa_request"),
                  44 => array("CoA-ACK",            null ),
                  45 => array("CoA-NAK",            null ),
);

function resposta($code, $sock, $client_ip , $client_ip) {
  //$pkt = 0x2c920000;//, 253, 20, 0x8f, 0x94, 0x48, 0x7b, 0x48, 0x12, 0xcd, 0x68, 0x95, 0x6c, 0xfa, 0x42, 0x70, 0x57, 0x26, 0x1b);
  $pkt = 0x0000922c;
  $buf = pack("c", $pkt);
    if (!socket_sendto($sock, $buf , count($buf) , 0 , $client_ip , $client_port)) {
      echo "socket_sendto() failed: reason: " . socket_strerror(socket_last_error($msgsock)) . "\n";
    }
}

function dbg() {
  $arg = func_get_args();
  $arg[0] = sprintf("**dbg(): %s \n", $arg[0]);
  call_user_func_array("printf", $arg);
}

function get_request($packet) {
	GLOBAL $code_map;
	$byte0 = ord($packet[0]);

	if (@array_key_exists($byte0, $code_map)) {
    $obj = new StdClass;

    $map = $code_map[$byte0];
    $obj->code = $map[0];
    $obj->cb = $map[1];

		return $obj;
	} else {
		return null;
	}
}

// socket settings
if (($sock = socket_create(AF_INET, SOCK_DGRAM, 0)) === false) {
    dbg("socket_create() failed: reason: %s ", socket_strerror(socket_last_error()));
}

if (socket_bind($sock, "0.0.0.0", $port) === false) {
    dbg("socket_bind() failed: reason: %s", socket_strerror(socket_last_error($sock)));
}

dbg("/* Iniciando Servidor RadiusFake {auth, coa} : na porta udp://$port */");

// busyloop()
do {
  $payload = null;

  $socklen = socket_recvfrom ($sock, $payload, 512, 0, $client_ip, $client_port);       
  if (!$socklen) {
    dbg("** AVISO: socket_read() failed: reason: " . socket_strerror(socket_last_error($msgsock)));
    break 2;
  }

  dbg("** Recebendo %d pacotes de $client_ip:$client_port>", count($socklen));

  // dump
  /*echo "<dump packet received from $client_ip:$client_port>\n";
  echo bin2hex($buf);
  echo "</dump>\n";*/

  // core
  $request = get_request($payload[0]);
  if (!$request) {
    dbg("WARNING: The %d is a uknown code, ignoring.", $request->code);
    continue;
  }
  
  dbg("[<<] Receiving the packet '%s', calling %s()", $request->code, $request->cb);

  if (!function_exists($request->cb)) {
    dbg("ERROR: The callback %s() don't exist, ignoring.\n", $request->cb);
    continue;
  }

  if(!call_user_func($request->cb, $payload, $client_ip , $client_port)) {
    dbg("the callback %s() return false", $request->cb);
  }

  // continue
  $qtd++;
} while (true);

socket_close($sock);

echo "Finalizando Servidor\n";
?>
