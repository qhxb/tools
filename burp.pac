function FindProxyForURL(url, host)
{
    url  = url.toLowerCase();
    host = host.toLowerCase();
    if (shExpMatch(url,"*icloud*")  ||
        shExpMatch(url,"*apple*") ||
        shExpMatch(url,"*baidu*")) {
	        return "DIRECT";
		};
    return "PROXY 10.91.51.110:8888";
}
