<?php
	include('logging.php');

	function ip($line) {
		// Set this to something unique ! (md5(time()); for example ...)
		$serverseed = "lvc1jy3w4i3rnzvho79r4tqp2hzol9l0zytxee35p7v14jugsyfa5ogyxuh0uv1y";
		$cancreate  = true;

		// parse and get record data.
		$record = null;
		if(isset($_GET['record']) && is_string($_GET['record'])) {
			$record = false;
			if(preg_match("/[0-9a-z]{2,40}/", strtolower($_GET['record']))) {
				// search into our DB
				$lines = file(__FILE__);
				for( $i = count($lines) - 1; $i > $line + 2; $i--) {
					$recordarray = preg_split('/^([0-9\.]+)\s+([0-9a-z]{2,40})/', $lines[$i], null , PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
					if(count($recordarray) > 2) { // means valid record.
						if($recordarray[1] === $_GET['record']) {
							if(!filter_var($recordarray[0], FILTER_VALIDATE_IP))
								throw new Exception("Error record for '".$recordarray[1]."' does not contain a valid ip, try deleting or manually change", 1);
							$record = array('name' => $_GET['record'], 'ip' => $recordarray[0], 'id' => $i);
							break; // exit loop
						}
					}
				}
			}
		}

		$auth = null;
		if(is_array($record) && isset($_GET['auth']) && is_string($_GET['auth'])) {
			$auth = false;
			if(!preg_match("/[0-9a-f]{42}/", strtolower($_GET['auth']))) // valid md5
				throw new Exception("Error parameter auth does not contain a valid md5 string", 1);
			$salt = substr($_GET['auth'], -10); // get salt
			// echo md5($record['ip'].$record['name'].$serverseed.$salt).$salt;
			if(md5($record['ip'].$record['name'].$serverseed.$salt).$salt === $_GET['auth'])
				$auth = true; // we have a valid authentification !
		}

		// ip exist and is valid ? use it
		$ip = getenv('REMOTE_ADDR'); // else use ip of caller
		if(isset($_GET['ip']) && is_string($_GET['ip'])) {
			if(!filter_var($_GET['ip'], FILTER_VALIDATE_IP))
				throw new Exception("Error invalid ip given for parameter ip", 1);
			$ip = $_GET['ip'];
		}

		if(isset($_GET['action']) && is_string($_GET['action'])) {
			switch ($_GET['action']) {
				case 'update':
					// record do not exist ? error
					if($record === null) throw new Exception("Error parameter record must be specified for an update", 1);
					if(!is_array($record)) throw new Exception("Error this record does not exist", 1);
					
					// valid auth ?
					if($auth === null) throw new Exception("Error no authentification token given", 1);
					if($auth !== true) throw new Exception("Error invalid authentification token", 1);
					
					// do update
					$lines[$record['id']] = $ip . str_repeat(" ", 18 - strlen($ip)) . $record['name'] . "\r\n";
					$fp = fopen(__FILE__ , "w"); 		// open this script for writting
					fputs($fp , implode("", $lines)); 	// write all lines
					fclose($fp); 						// close buffer

					// send new auth cookie
					$salt = substr(md5($ip.$record['name'].$serverseed.$salt),0,10);
					echo "Update done on record ".$record['name']." to ip: ".$ip."<br />\n";
					echo "AuthToken: ".md5($ip.$record['name'].$serverseed.$salt).$salt;
					break;
				case 'get':
					// record do not exist ? error
					if($record === null) throw new Exception("Error parameter record must be specified for a get", 1);
					if(!is_array($record)) throw new Exception("Error this record does not exist", 1);
					// return record data
					echo $record['ip'];
					break;
				case 'create':
					if(!$cancreate) throw new Exception("Error can not create new record because configuration does not allow it", 1);
					// record exist ? error
					if($record === null) throw new Exception("Error parameter record must be specified for a create", 1);
					if($record !== false) throw new Exception("Error can not create this record because it already exist, try deleting it first", 1);
					// create and give auth cookie
					$lines[] = $ip . str_repeat(" ", 18 - strlen($ip)) . $_GET['record'] . "\n";
					$fp = fopen(__FILE__ , "w"); 		// open this script for writting
					fputs($fp , implode("", $lines)); 	// write all lines
					fclose($fp); 						// close buffer
					$salt = substr(md5(time()), 0, 10);
					echo "AuthToken: ".md5($ip.$_GET['record'].$serverseed.$salt).$salt;
					break;
				case 'delete':
					// record do not exist ? error
					if($record === null) throw new Exception("Error parameter record must be specified for a delete", 1);
					if(!is_array($record)) throw new Exception("Error this record does not exist", 1);
					// valid auth ? remove
					if($auth === null) throw new Exception("Error no authentification token given", 1);
					if($auth !== true) throw new Exception("Error invalid authentification token", 1);

					// do update
					$lines[$record['id']] = ""; 		// delete line
					$fp = fopen(__FILE__ , "w"); 		// open this script for writting
					fputs($fp , implode("", $lines)); 	// write all lines
					fclose($fp); 						// close buffer
					
					break;
				default:
					throw new Exception("Error parameter action can only be get/create/update/delete", 1);
			}
		}
	}
	try {
		ip(__LINE__);
	} catch(Exception $e) {
		echo $e->getMessage();
	}
	exit();
?>
<!--    IPS DATABASE 
IP                NAME -->
70.83.0.226       test
109.213.97.110    raspberry
