#!/usr/bin/php -q
<?php
/**
 * Author: Jorge Pereira <jorge.pereira@mobicare.com.br>
 * Seguindo a rfc https://tools.ietf.org/html/rfc5176

  

/* config set */
$port = 1812;
$qtd = 1;
$secret = "testing123";

/* debug options */
error_reporting(E_ALL);

/* Allow the script to hang around waiting for connections. */
set_time_limit(0);

/* Turn on implicit output flushing so we see what we're getting
 * as it comes in. */
ob_implicit_flush();

/* helpers */

function dbg() {
  $arg = func_get_args();
  $arg[0] = sprintf("**dbg(): %s \n", $arg[0]);
  call_user_func_array("printf", $arg);
}

function dump_hex($pkt) {
  echo "<hexdump>\n";
  echo "{ ";
  for ($i=0; $i < count($pkt); $i++) {
    $ch = ($pkt[$i]);
    printf("0x%x, ", $ch);
  }
  echo "} \n</hexdump>\n";
}

/**/
function set_authenticator(&$pkt) {
  for ($i=0; $i < 16; $i++) {
    $pkt[$i+4] = rand() & 0xff;
  }
}

/* handlers */
function cb_coa_request($payload, $sock, $client_ip, $client_port) {
  $pkt = array();

  dbg("[<<] Response the request with CoA-ACK.");

  $pkt[0] = 44;               // CoA-ACK
  $pkt[1] = ord($payload[1]); // identifier
  $pkt[2] =  0;               // length
  $pkt[3] = 20;               // length
  set_authenticator($pkt);    // authenticator

//  dump_hex($pkt);
  
  return wrapper_send($pkt, $sock, $client_ip, $client_port);
}

function cb_access_request($payload, $sock, $client_ip, $client_port) {
  echo "STUB: cb_access_request()";
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

function wrapper_send($payload /* array data: eg: array(1, 23, 00, 22, 111)*/,
                      $sock,
                      $client_ip,
                      $client_port) {
  $bytes = call_user_func_array("pack", array_merge(array("C*"), $payload));

  $ret = socket_sendto($sock, $bytes, strlen($bytes), 0 , $client_ip, $client_port);
  if (!$ret) {  
    echo "socket_sendto(): failed: reason: " . socket_strerror(socket_last_error()) . "\n";
    return false;
  }
  return true;
}

function get_request_type($packet) {
	GLOBAL $code_map;
	$byte0 = ord($packet[0]);

	if (@array_key_exists($byte0, $code_map)) {
    $obj = new StdClass;

    $map = $code_map[$byte0];
    $obj->code = $map[0];
    $obj->identifier = ord($packet[1]);
    $obj->length = ord($packet[3]);
    $obj->callback = $map[1];

		return $obj;
	} else {
		return null;
	}
}

// socket settings
if (($sock = socket_create(AF_INET, SOCK_DGRAM, 0)) === false) {
    dbg("ERROR: socket_create() failed: reason: %s ", socket_strerror(socket_last_error()));
    exit(-1);
}

if (socket_bind($sock, "0.0.0.0", $port) === false) {
    dbg("ERROR: socket_bind() failed: reason: %s", socket_strerror(socket_last_error($sock)));
    exit(-1);
}

dbg("/* Iniciando Servidor RadiusFake {auth, coa} : na porta udp://$port */");

// busyloop()
do {
  $payload = null;

  dbg("Waiting requests.");

  if (!($socklen = socket_recvfrom ($sock, $payload, 512, 0, $client_ip, $client_port))) {
    dbg("WARNING: socket_read() failed: reason: " . socket_strerror(socket_last_error($msgsock)));
    break 2;
  }

  dbg("** Recebendo %d pacotes de $client_ip:$client_port>", count($socklen));

  // core
  $request = get_request_type($payload);
  if (!$request) {
    dbg("WARNING: The %d is a uknown code, ignoring.", $payload[0]);
    dump_hex($payload);
    continue;
  }
  
  dbg("[>>] Receiving the packet '%s' identifier=%d length=%d, calling %s()",
            $request->code, $request->identifier, $request->length, $request->callback
  );

  if (!function_exists($request->callback)) {
    dbg("ERROR: The callback %s() don't exist, ignoring.\n", $request->callback);
    continue;
  }
  
  if(!call_user_func($request->callback, $payload, $sock, $client_ip, $client_port)) {
    dbg("the callback %s() return false", $request->callback);
  }

  // continue
  $qtd++;
} while (true);

socket_close($sock);

echo "Finalizando Servidor\n";
?>
