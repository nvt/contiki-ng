TIMEOUT(600000);

/* The flow-control test passes only when both the client has finished
   sending its stream ("Test OK") and the server has validated every
   byte across all three retention phases ("Server OK"). */
var client_ok = false;
var server_ok = false;

while (true) {
  log.log(time + ":" + id + ":" + msg + "\n");
  if (msg.indexOf('Test OK') != -1) {
    client_ok = true;
  }
  if (msg.indexOf('Server OK') != -1) {
    server_ok = true;
  }
  if (client_ok && server_ok) {
    log.testOK();
  }
  YIELD();
}
