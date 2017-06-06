<?php
/* Sample port knock client in PHP */
/*
 * Packet payload consists of a timestamp:ipaddress:services
 * where ipaddress is the external ip address and services a
 * comma separated list of services defined in Issabel Firewall
 */
$server_ip   = '127.0.0.1';
$server_port = 12343;
$user        = 'admin';
$password    = 'password';
$services   = 'HTTPS,SSH';

$tstamp = time();
$externalContent = file_get_contents('http://checkip.dyndns.com/');
preg_match('/Current IP Address: \[?([:.0-9a-fA-F]+)\]?/', $externalContent, $m);
$externalIp = $m[1];

$data         = "$tstamp:$externalIp:$services";
$md5_password = md5($password);
$payload      = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $md5_password, $data, MCRYPT_MODE_CBC, md5($md5_password)));

print "Sending knock to IP $server_ip, port $server_portn for user $user, data $data, payload $payload\n\n";

$message = "$user:$payload";

if ($socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP)) {
    socket_sendto($socket, $message, strlen($message), 0, $server_ip, $server_port);
} else {
  echo "error\n";
}
?>
