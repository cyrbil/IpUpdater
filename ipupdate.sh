#!/bin/sh
# upupdate.sh
####################################
# Send our actual ip to the server #
# that store ip.                   #
####################################

UPDATE_URL=${1-"http://server.fr/ip.php"};
NAME=${2-"servername"};
# auth is a token given by the server, if lost ip update won't be possible.
AUTH="";

# auth is empty, we need to create new record first
if [ -z "$AUTH" ]; then
    QUERY="$UPDATE_URL?action=create&record=$NAME"
else
    QUERY="$UPDATE_URL?action=update&record=$NAME&auth=$AUTH"
fi

echo "Querying: $QUERY";
RESULT=`wget -q -O - "$QUERY"` || `echo "Error when trying to query server ..." && exit 1`;
# parse result to see if we got a authtoken
echo $RESULT | grep -E -q 'AuthToken: \w{42}';
if [ $? -eq 0 ]; then
    # save it
    TOKEN=`echo "$RESULT" | grep -E 'AuthToken: \w{42}' | sed -r 's/.*([a-f0-9]{42})/\1/'`;
    echo "Saving token $TOKEN";
    sed -i "s/^AUTH=\".*\";/AUTH=\"${TOKEN}\";/g" "${BASH_SOURCE[0]}";
    echo "OK";
else
    echo "Server return an error: $RESULT";
fi