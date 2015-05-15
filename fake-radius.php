#!/usr/bin/php -q
<?php
/**
 * Author: Jorge Pereira <jorge.pereira@mobicare.com.br>
 * Seguindo a rfc https://tools.ietf.org/html/rfc5176

   # pacote coa
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Authenticator                         |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code
   40 - Disconnect-Request [RFC3575]
   41 - Disconnect-ACK [RFC3575]
   42 - Disconnect-NAK [RFC3575]
   43 - CoA-Request [RFC3575]
   44 - CoA-ACK [RFC3575]
   45 - CoA-NAK [RFC3575]

   Identifier
 */
error_reporting(E_ALL);

/* Allow the script to hang around waiting for connections. */
set_time_limit(0);

/* Turn on implicit output flushing so we see what we're getting
 * as it comes in. */
ob_implicit_flush();

$port = 1812;
$qtd = 1;
$vsa_code = array( /* Codes: Radius-Auth */
                   1 => "Access-Request",
                   2 => "Access-Accept",
                   3 => "Access-Reject",
                   4 => "Accounting-Request",
                   5 => "Accounting-Response",
                  11 => "Access-Challenge",

                  /* Codes: CoA */
                  40 => "Disconnect-Request",
                  41 => "Disconnect-ACK",
                  42 => "Disconnect-NAK",
                  43 => "CoA-Request",
                  44 => "CoA-ACK",
                  45 => "CoA-NAK",
);

function resposta($code, $sock, $rmt_ip , $rmt_port) {
  //$pkt = 0x2c920000;//, 253, 20, 0x8f, 0x94, 0x48, 0x7b, 0x48, 0x12, 0xcd, 0x68, 0x95, 0x6c, 0xfa, 0x42, 0x70, 0x57, 0x26, 0x1b);
  $pkt = 0x0000922c;
  $buf = pack("c", $pkt);
    if (!socket_sendto($sock, $buf , count($buf) , 0 , $rmt_ip , $rmt_port)) {
      echo "socket_sendto() failed: reason: " . socket_strerror(socket_last_error($msgsock)) . "\n";
    }
}

function dbg($str) {

}
function get_packet_vsa($packet) {
	GLOBAL $vsa_code;
	$code = ord($packet[0]);

	if (@array_key_exists($code, $vsa_code)) {
    $vsa = $vsa_code[$code];
    echo "<< Recebido um pacote $code ($vsa)\n";
		return $vsa;
	} else {
		return null;
	}
}

/////////////////////////////////////////////////////////////////////////////////

if (($sock = socket_create(AF_INET, SOCK_DGRAM, 0)) === false) {
    echo "socket_create() failed: reason: " . socket_strerror(socket_last_error()) . "\n";
}

if (socket_bind($sock, "0.0.0.0", $port) === false) {
    echo "socket_bind() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n";
}

echo "/* Iniciando Servidor RadiusFake {auth, coa} : na porta udp://$port */\n";

do {
  $payload = null;

  $socklen = socket_recvfrom ($sock, $payload, 512, 0, $rmt_ip, $rmt_port);       
  if (!$socklen) {
    echo "** AVISO: socket_read() failed: reason: " . socket_strerror(socket_last_error($msgsock)) . "\n";
    break 2;
  }

  printf("[$qtd] ** Recebendo %d pacotes de $rmt_ip:$rmt_port>\n", count($socklen));

  // dump
  echo "<dump packet received from $rmt_ip:$rmt_port>\n";
  echo bin2hex($buf);
  echo "\n</dump>\n";

  // core
  $Code = get_packet_vsa($payload[0]);
  if ($code == null)
  {
    echo "** AVISO: O Codigo $"
  }
  switch($code) {
    case "CoA-Request":
      resposta("CoA-ACK", $sock, $rmt_ip , $rmt_port);
    break;

    default:
      echo "AVISO: O Codigo '$code' e desconhecido.";
  }

  // resposta

  // end
  $qtd++;
} while (true);

socket_close($sock);

echo "Finalizando Servidor\n";
?>
