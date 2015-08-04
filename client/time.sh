#!/bin/bash

UPDATE='python sse_client.py -u'
SEARCH='python sse_client.py -s'

# 10 files to UPDATE
FILES=('1.' '12.' '15.' '18.' '20.' '23.' '26.' '29.' '31.' '34.') # '37.' '4.' '42.' '45.' '62.' '65.' '68.' '70.' '73.' '78.') # '83.' '86.');

# 10 'known' terms
TERMS=('such') # 'tuesday' 'pm' 'message' 'if' 'but' 'very' 'problem' 'see' 'the')

# 5 'unknown' terms
UNKNOWN=('beluga' 'whippersnapper' 'cufflink' 'grigsby' 'described')

for i in "${TERMS[@]}"; do
    echo "$SEARCH $i"
    $SEARCH $i
done
exit 0
rm index*
rm ../server/index
for i in "${FILES[@]}"; do
    echo "$UPDATE inbox/$i"
    $UPDATE inbox/$i
done
exit 0


for i in "${UNKNOWN[@]}"; do
    echo "$SEARCH $i";
    $SEARCH $i
done
