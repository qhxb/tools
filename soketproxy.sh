echo soket proxy $1
if [ $1 == 'start' ]; then
nohup python -u proxy.py start >> proxy.log 2>&1 &
elif [ $1 == 'end' ]; then
pids=$(ps -ef|grep "python -u proxy.py start"|grep -v grep |awk '{print $2}')
for i in $pids
do
kill -9 $i
done
nohup python -u proxy.py end
fi
