# The IP addresses are hardcoded as OPNsense does not provide a clear way to specify
# "WireGuard DNS server", so it's not templated with Jinja2.
DNS2TUN_OUT_IF := 0.0.0.0
DNS2TUN_FWD_TO := 0.0.0.0
DNS2TUN_IPV4 := 127.4.51.53
DNS2TUN_PORT := 53451

# See https://docs.opnsense.org/development/backend/templates.html
VENDOR := b4cksp4ce
APP := ip-forward

V2FLY_SERVICES := \
    cisco \
    dell \
    discord \
    facebook \
    facebook-ads \
    instagram \
    instagram-ads \
    intel \
    intel-dev \
    netflix \
    openai \
    qualcomm \
    signal \
    tailscale \
    twitter \
    x \
    xai \
    youtube

-include local.conf.mk

WEB_SOURCES := \
    share/antifilter-community.txt \
    share/fz139-resolves.zip \
    share/fz139-vigruzki.zip \
    share/iana-tlds.txt \
    share/public_suffix_list.dat \
    share/tor-auth-dirs.inc \
    share/tor-fallback-dirs.inc \
    share/tor-microdesc \
    share/v2fly-community.zip

SORT_U := LC_ALL=C sort --unique
AGGREGATE_IPV4 := sed '/\// ! s,$$,/32,' | aggregate | sed 's,/32$$,,'

.PHONY : all fetch build install clean distclean
.PRECIOUS : $(WEB_SOURCES)

all : build
fetch : $(WEB_SOURCES)
build : fetch
install : build

clean :
	git clean -dfx tmp var
distclean :
	git clean -dfx -e local.conf.mk .

########################################################################
# Sources

share/iana-tlds.txt :
	lib/dl https://data.iana.org/TLD/tlds-alpha-by-domain.txt $@
share/fz139-resolves.zip :
	lib/dl https://github.com/fz139/blocked-domains-resolves/archive/refs/heads/main.zip $@
share/fz139-vigruzki.zip :
	lib/dl https://github.com/fz139/vigruzki/archive/refs/heads/main.zip $@
share/public_suffix_list.dat :
	lib/dl https://publicsuffix.org/list/public_suffix_list.dat $@
share/v2fly-community.zip :
	lib/dl https://github.com/v2fly/domain-list-community/archive/refs/heads/master.zip $@
share/antifilter-community.txt :
	lib/dl https://community.antifilter.download/list/domains.lst $@
share/tor-auth-dirs.inc :
	lib/dl https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/auth_dirs.inc?inline=false $@
share/tor-fallback-dirs.inc :
	lib/dl https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc?inline=false $@
share/tor-microdesc : share/tor-auth-dirs.inc
	for endpoint in `sed -E '/^[[:space:]]+"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+[[:space:]]/ ! d; s,^[[:space:]]*",,; s,[[:space:]].*,,; s,:80,,' share/tor-auth-dirs.inc`; do \
		lib/dl http://$${endpoint}/tor/status-vote/current/consensus-microdesc $@ && break; \
	done

########################################################################
# IANA TLD list derivatives, see https://www.iana.org/domains/root/files

########################################################################
# @roscomnadzor's https://vigruzki.rkn.gov.ru derivatives

tmp/blocked-domains-resolves/rvzdata.json : share/fz139-resolves.zip
	unzip -o -d tmp/ share/fz139-resolves.zip
	touch -r tmp/blocked-domains-resolves/rvzdata.json share/fz139-resolves.zip
tmp/dump.json.gz : share/fz139-vigruzki.zip
	unzip -p share/fz139-vigruzki.zip 'vigruzki-main/dump.xml.[0-9]*' \
		| lib/vigruzki2js >tmp/dump.json
	gzip tmp/dump.json
tmp/rvzdata.nxdomain : share/fz139-resolves.zip
	unzip -p share/fz139-resolves.zip blocked-domains-resolves-main/rvzdata.json | jq -r '.list[] | select(.rc == "NXDOMAIN") | .d' | $(SORT_U) >$@
tmp/dns.fz139.gz : tmp/dump.json.gz share/iana-tlds.txt tmp/rvzdata.nxdomain share/public_suffix_list.dat
	zcat tmp/dump.json.gz \
		| jq -r '.domain[], .mask[]' \
		| lib/sed-domain share/iana-tlds.txt \
		| grep --invert-match --fixed-strings --line-regexp -f tmp/rvzdata.nxdomain \
		| lib/psl-reg-domain share/public_suffix_list.dat \
		| $(SORT_U) \
		| gzip >$@
tmp/ipv4.fz139.gz : tmp/dump.json.gz
	zcat tmp/dump.json.gz \
		| jq -r '.ip4[], .net4[]' \
		| $(SORT_U) --version-sort \
		| gzip >$@
tmp/ipv6.fz139.gz : tmp/dump.json.gz
	zcat tmp/dump.json.gz \
		| jq -r '.ip6[], .net6[]' \
		| $(SORT_U) --version-sort \
		| gzip >$@

########################################################################
# v2fly, Project V derivatives

tmp/v2fly.includes :
	echo $(V2FLY_SERVICES) | sed -E 's,[[:space:]]+,\n,g' | sed -E '/^$$/d; s/^/include:/' >$@
tmp/dns.v2fly.gz : share/v2fly-community.zip tmp/v2fly.includes share/iana-tlds.txt
	unzip -p share/v2fly-community.zip `echo $(V2FLY_SERVICES) | sed 's,\(^\| \),&domain-list-community-master/data/,g'` \
		| grep --invert-match --fixed-strings --line-regexp -f tmp/v2fly.includes \
		| sed -E 's,^full:,,; s,[[:space:]]*[@#].*$$,,; /^[[:space:]]*$$/d' \
		| lib/sed-domain share/iana-tlds.txt \
		| gzip >$@

########################################################################
# Antifilter.Download, community edition derivatives

tmp/fz139-v2fly.regex : tmp/dns.v2fly.gz tmp/dns.fz139.gz
	zcat tmp/dns.v2fly.gz tmp/dns.fz139.gz \
		| sed -E 's,\.,\\.,g; s,^,\\(^\\|\\.\\),; s,$$,$$,' \
		| $(SORT_U) >$@
tmp/antifilter-extra.txt : share/antifilter-community.txt tmp/fz139-v2fly.regex
	rm -f tmp/fz139-v2fly.regex.*
	split -d -l 10000 tmp/fz139-v2fly.regex tmp/fz139-v2fly.regex.
	cp share/antifilter-community.txt tmp/antifilter-extra.txt
	for fre in tmp/fz139-v2fly.regex.*; do \
		grep --invert-match -f $${fre} tmp/antifilter-extra.txt >tmp/antifilter-extra.txt.next; \
		rm -f $${fre}; \
		mv tmp/antifilter-extra.txt.next tmp/antifilter-extra.txt; \
	done
tmp/dns.antifilter.gz : tmp/antifilter-extra.txt share/public_suffix_list.dat
	grep --invert-match -e '\.google\.com$$' tmp/antifilter-extra.txt \
		| lib/psl-reg-domain share/public_suffix_list.dat \
		| $(SORT_U) >tmp/dns.antifilter
	grep -e '\.google\.com$$' tmp/antifilter-extra.txt >>tmp/dns.antifilter
	gzip tmp/dns.antifilter

########################################################################
# Tor, The Onion Router network

tmp/ipv4.tor.gz : share/tor-auth-dirs.inc share/tor-fallback-dirs.inc share/tor-microdesc
	sed -E '/^[[:space:]]+"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+[[:space:]]/ ! d; s,^[[:space:]]*",,; s,:.*,,' share/tor-auth-dirs.inc >tmp/ipv4.tor
	sed -E '/^[[:space:]]+"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]/ ! d; s,^[[:space:]]*",,; s,[[:space:]].*,,' share/tor-fallback-dirs.inc >>tmp/ipv4.tor
	awk '($$1 == "r") { print $$6 }' share/tor-microdesc >>tmp/ipv4.tor
	gzip tmp/ipv4.tor

########################################################################
# `build`

var/dns.gz : tmp/dns.fz139.gz tmp/dns.v2fly.gz tmp/dns.antifilter.gz share/iana-tlds.txt
	zcat tmp/dns.fz139.gz tmp/dns.v2fly.gz tmp/dns.antifilter.gz \
		| lib/sed-domain share/iana-tlds.txt \
		| $(SORT_U) \
		| gzip >$@

var/ipv4.gz : tmp/ipv4.fz139.gz tmp/ipv4.tor.gz
	zcat tmp/ipv4.fz139.gz tmp/ipv4.tor.gz \
		| $(AGGREGATE_IPV4) \
		| $(SORT_U) --version-sort \
		| gzip >$@

# It might be wrong for several reasons. Here is one of them: CNAMEs are chased by Unbound itself,
# asking the remote server for every name in the indirection chain.
var/unbound.opnsense.forward-to-dns2tun.conf.gz : var/dns.gz local.conf.mk
	zcat var/dns.gz \
		| sed 's/.*/forward-zone:\n name: "&."\n forward-addr: $(DNS2TUN_IPV4)@$(DNS2TUN_PORT)\n forward-no-cache: yes/' \
		| gzip >"$@"

var/unbound.rc.local-tlds-ipset.conf.gz : share/iana-tlds.txt
	sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/; /^#/d; s/.*/local-zone: "&." ipset/' share/iana-tlds.txt \
		| gzip >"$@"

var/unbound.rc.dns2tun.conf : share/unbound-dns2tun.conf local.conf.mk
	sed \
		-e 's,@@DNS2TUN_IPv4@@,$(DNS2TUN_IPV4),' \
		-e 's,@@DNS2TUN_PORT@@,$(DNS2TUN_PORT),' \
		-e 's,@@DNS2TUN_OUT_IF@@,$(DNS2TUN_OUT_IF),' \
		-e 's,@@DNS2TUN_FWD_TO@@,$(DNS2TUN_FWD_TO),' \
		<share/unbound-dns2tun.conf >$@

build : var/unbound.opnsense.forward-to-dns2tun.conf.gz
build : var/unbound.rc.dns2tun.conf
build : var/unbound.rc.local-tlds-ipset.conf.gz
build : var/ipv4.gz

########################################################################
# `install`

# /usr/local/opnsense/service/templates/$(VENDOR)/$(APP)/ can't handle large
# configuration file and OOMs. So, here is the hack.
install : \
		/usr/local/etc/rc.syshook.d/early/50-ip2tun \
		/var/db/aliastables/ip2tun.gz \
		/var/run/unbound-dns2tun.pid
	make -j1 /var/run/unbound.pid
	/usr/local/etc/rc.syshook.d/early/50-ip2tun

/usr/local/etc/unbound/dns2tun.conf : var/unbound.rc.dns2tun.conf
	cp var/unbound.rc.dns2tun.conf $@
/usr/local/etc/unbound/local-tlds-ipset.conf : var/unbound.rc.local-tlds-ipset.conf.gz
	cp var/unbound.rc.local-tlds-ipset.conf.gz $@.gz
	gunzip $@.gz
/etc/rc.conf.d/unbound : share/unbound.rc
	cp share/unbound.rc $@
/usr/local/etc/unbound/dns2tun/unbound_server.pem :
	mkdir -p /usr/local/etc/unbound/dns2tun
	unbound-control-setup -d /usr/local/etc/unbound/dns2tun
/var/run/unbound-dns2tun.pid : \
		/etc/rc.conf.d/unbound \
		/usr/local/etc/unbound/dns2tun.conf \
		/usr/local/etc/unbound/dns2tun/unbound_server.pem \
		/usr/local/etc/unbound/local-tlds-ipset.conf
	service unbound restart

/usr/local/etc/unbound.opnsense.d/forward-to-dns2tun.conf : var/unbound.opnsense.forward-to-dns2tun.conf.gz
	cp var/unbound.opnsense.forward-to-dns2tun.conf.gz $@.gz
	gunzip $@.gz
/var/run/unbound.pid : /usr/local/etc/unbound.opnsense.d/forward-to-dns2tun.conf
	pluginctl -s unbound restart

/usr/local/etc/rc.syshook.d/early/50-ip2tun : share/ip2tun
	cp share/ip2tun $@
	chmod 755 $@
/var/db/aliastables/ip2tun.gz : var/ipv4.gz
	cp var/ipv4.gz $@

deinstall :
	rm -f /usr/local/etc/unbound.opnsense.d/forward-to-dns2tun.conf
	pluginctl -s unbound restart
	service unbound stop
	rm -f /usr/local/etc/unbound/dns2tun.conf /usr/local/etc/unbound/local-tlds-ipset.conf /etc/rc.conf.d/unbound
	rm -f /var/db/aliastables/ip2tun.gz /usr/local/etc/rc.syshook.d/early/50-ip2tun
