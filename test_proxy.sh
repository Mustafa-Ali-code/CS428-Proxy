#!/bin/bash
for i in {1..10}  # Adjust the number for more or fewer concurrent requests
do
   curl -x http://localhost:15213 http://facebook.com &
done
wait
echo "All requests completed."