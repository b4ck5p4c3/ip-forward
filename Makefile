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
    notion \
    openai \
    qualcomm \
    signal \
    tailscale \
    twitter \
    x \
    xai \
    youtube

AS_AMAZON_02 := AS16509
AS_CLOUDFLARENET := AS13335
AS_DIGITALOCEAN := AS14061
AS_HETZNER := AS24940
AS_OVH := AS16276
AS2TUN := \
    $(AS_AMAZON_02) \
    $(AS_CLOUDFLARENET) \
    $(AS_DIGITALOCEAN) \
    $(AS_HETZNER) \
    $(AS_OVH)

-include local.conf.mk

WEB_SOURCES := \
    share/antifilter-community.txt \
    share/cloudflare-ips-v4 \
    share/fz139-resolves.zip \
    share/fz139-vigruzki.zip \
    share/iana-tlds.txt \
    share/public_suffix_list.dat \
    share/tor-auth-dirs.inc \
    share/tor-fallback-dirs.inc \
    share/tor-microdesc \
    share/v2fly-community.zip

SORT_U := LC_ALL=C sort --unique

.PHONY : all \
	depends fetch build \
	install \
	install-mgmt \
	install-speedtest \
	install-unbound \
	upgrade-unbound \
	install-2tun \
	up \
	clean distclean \
	deinstall-2tun \
	deinstall
.PRECIOUS : $(WEB_SOURCES)

all : build
fetch : $(WEB_SOURCES)
build : fetch depends
install : build install-mgmt install-2tun

depends : \
	/usr/local/bin/aggregate \
	/usr/local/bin/jq \
	/usr/local/bin/nping \
	/bin/sh
up :
	git pull --ff-only
clean :
	git clean -dfx tmp var
distclean :
	git clean -dfx -e local.conf.mk .

########################################################################
# Packages

/usr/local/bin/aggregate : /usr/local/etc/pkg/repos/ip-forward.conf
	pkg install -y aggregate
/usr/local/bin/jq :
	pkg install -y jq
/usr/local/bin/nping :
	pkg install -y nmap

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
share/cloudflare-ips-v4 :
	lib/dl https://www.cloudflare.com/ips-v4 $@
tmp/announced-prefixes-v4.gz :
	for as in $(AS2TUN); do \
		lib/dl https://stat.ripe.net/data/announced-prefixes/data.json?resource=$${as} share/announced-prefixes-$${as} ; \
		jq -r '.data.prefixes[].prefix | select(contains(":") | not)' <share/announced-prefixes-$${as} ; \
	done \
		| lib/aggregate \
		| $(SORT_U) --version-sort \
		| gzip >$@

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
	gzip -f tmp/dump.json
tmp/rvzdata.nxdomain : share/fz139-resolves.zip
	unzip -p share/fz139-resolves.zip blocked-domains-resolves-main/rvzdata.json | jq -r '.list[] | select(.rc == "NXDOMAIN") | .d' | $(SORT_U) >$@
tmp/dns.fz139.gz : tmp/dump.json.gz share/iana-tlds.txt tmp/rvzdata.nxdomain share/public_suffix_list.dat
	zcat tmp/dump.json.gz \
		| jq -r '.domain[], .mask[]' \
		| lib/sed-domain share/iana-tlds.txt \
		| lib/grep-vFxf tmp/rvzdata.nxdomain \
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
	unzip -p share/v2fly-community.zip `echo $(V2FLY_SERVICES) | sed -E 's,(^|[[:space:]]),&domain-list-community-master/data/,g'` \
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
	gzip -f tmp/dns.antifilter

########################################################################
# Tor, The Onion Router network

tmp/ipv4.tor.gz : share/tor-auth-dirs.inc share/tor-fallback-dirs.inc share/tor-microdesc
	sed -E '/^[[:space:]]+"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+[[:space:]]/ ! d; s,^[[:space:]]*",,; s,:.*,,' share/tor-auth-dirs.inc >tmp/ipv4.tor
	sed -E '/^[[:space:]]+"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]/ ! d; s,^[[:space:]]*",,; s,[[:space:]].*,,' share/tor-fallback-dirs.inc >>tmp/ipv4.tor
	awk '($$1 == "r") { print $$6 }' share/tor-microdesc >>tmp/ipv4.tor
	gzip -f tmp/ipv4.tor

########################################################################
# Cloudflare. To ease ECH pain :-(

tmp/ipv4.cloudflare.gz : share/cloudflare-ips-v4
	grep ^ share/cloudflare-ips-v4 >tmp/ipv4.cloudflare # add newline if missing
	gzip tmp/ipv4.cloudflare

########################################################################
# `build`

var/dns.gz : tmp/dns.fz139.gz tmp/dns.v2fly.gz tmp/dns.antifilter.gz share/iana-tlds.txt share/dns2tun.txt
	zcat tmp/dns.fz139.gz tmp/dns.v2fly.gz tmp/dns.antifilter.gz \
		| cat - share/dns2tun.txt \
		| lib/sed-domain share/iana-tlds.txt \
		| $(SORT_U) \
		| gzip >$@

var/ipv4.gz : tmp/ipv4.fz139.gz tmp/ipv4.tor.gz tmp/ipv4.cloudflare.gz tmp/announced-prefixes-v4.gz
	zcat tmp/ipv4.fz139.gz tmp/ipv4.tor.gz tmp/ipv4.cloudflare.gz tmp/announced-prefixes-v4.gz \
		| lib/aggregate \
		| $(SORT_U) --version-sort \
		| gzip >$@

# It might be wrong for several reasons. Here is one of them: CNAMEs are chased by Unbound itself,
# asking the remote server for every name in the indirection chain.
var/unbound.opnsense.forward-to-dns2tun.conf.gz : var/dns.gz local.conf.mk
	echo server: >var/unbound.opnsense.forward-to-dns2tun.conf
	zcat var/dns.gz | sed 's/.*/ local-zone: "&." ipset/' >>var/unbound.opnsense.forward-to-dns2tun.conf
	zcat var/dns.gz | sed 's/.*/forward-zone:\n name: "&."\n forward-addr: 127.4.5.1\n forward-no-cache: yes/' >>var/unbound.opnsense.forward-to-dns2tun.conf
	gzip -f var/unbound.opnsense.forward-to-dns2tun.conf

var/unbound.rc.local-tlds-ipset.conf.gz : share/iana-tlds.txt
	sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/; /^#/d; s/.*/local-zone: "&." ipset/' share/iana-tlds.txt \
		| gzip >"$@"

build : var/unbound.opnsense.forward-to-dns2tun.conf.gz
build : var/unbound.rc.local-tlds-ipset.conf.gz
build : var/ipv4.gz

########################################################################
# `install-mgmt`

install-mgmt : \
	/etc/cron.d/ip-forward-kludges \
	/usr/local/etc/rc.syshook.d/monitor/25-wg-junk \
	/usr/local/etc/rc.syshook.d/start/81-dpinger-kludge \
	/usr/local/etc/rc.syshook.d/start/83-wg-kludge \
	/usr/local/libexec/dpinger-kludge \
	/usr/local/libexec/wg-kludge \
	/usr/local/sbin/gw-status \
	/usr/local/sbin/opnsense-api \
	/usr/local/sbin/unbound-control-opnsense \
	/usr/local/sbin/wg-junk

/etc/cron.d/ip-forward-kludges : share/cron /usr/local/libexec/wg-kludge /usr/local/libexec/dpinger-kludge /usr/local/sbin/pfgc /usr/local/bin/cron.sh
	cp share/cron $@
/usr/local/etc/rc.syshook.d/monitor/25-wg-junk : bin/syshook-wg-junk /usr/local/sbin/wg-junk
	cp bin/syshook-wg-junk $@
/usr/local/etc/rc.syshook.d/start/81-dpinger-kludge : bin/syshook-start-dpinger-kludge /usr/local/libexec/dpinger-kludge
	cp bin/syshook-start-dpinger-kludge $@
/usr/local/etc/rc.syshook.d/start/83-wg-kludge : bin/syshook-start-wg-kludge /usr/local/libexec/wg-kludge
	cp bin/syshook-start-wg-kludge $@
/usr/local/sbin/wg-junk : bin/wg-junk
	cp bin/wg-junk $@
/usr/local/libexec/wg-kludge : bin/wg-kludge /usr/local/sbin/wg-junk
	cp bin/wg-kludge $@
/usr/local/libexec/dpinger-kludge : bin/dpinger-kludge
	cp bin/dpinger-kludge $@
/usr/local/sbin/gw-status : bin/gw-status
	cp bin/gw-status $@
/usr/local/sbin/opnsense-api : bin/opnsense-api
	cp bin/opnsense-api $@
/usr/local/sbin/unbound-control-opnsense : bin/unbound-control-opnsense
	cp bin/unbound-control-opnsense $@
/usr/local/sbin/pfgc : bin/pfgc
	cp bin/pfgc $@
/usr/local/bin/cron.sh : bin/cron.sh /usr/local/bin/randsleep
	cp bin/cron.sh $@
/usr/local/bin/randsleep : bin/randsleep
	cp bin/randsleep $@

########################################################################
# `install-speedtest`

install-speedtest : /usr/local/bin/speedtest
/usr/local/bin/speedtest : # https://www.speedtest.net/apps/cli is FreeBSD-12 and -13, not -14 :-(
	pkg add --force https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-freebsd13-x86_64.pkg

########################################################################
# `install-unbound`

install-unbound : /usr/local/etc/pkg/repos/ip-forward.conf
	pkg update
	if ! pkg info unbound | grep -q 'IPSET\s*:\s*on\>'; then pkg upgrade -y --repository ip-forward unbound; fi
	pkg lock -y unbound

upgrade-unbound : /usr/local/etc/pkg/repos/ip-forward.conf
	pkg unlock -y unbound
	pkg upgrade -y --repository ip-forward unbound
	pkg lock -y unbound

/usr/local/etc/pkg/ip-forward.pub : share/pkg-ip-forward.pub
	cp share/pkg-ip-forward.pub $@
/usr/local/etc/pkg/repos/ip-forward.conf : share/repos-ip-forward.conf /usr/local/etc/pkg/ip-forward.pub /usr/local/opnsense/version/pkgs
	pkgs=`cat /usr/local/opnsense/version/pkgs` && sed "s,@@pkgs@@,$${pkgs}," <share/repos-ip-forward.conf >$@

########################################################################
# `install-vrrp`

install-vrrp :	/boot/loader.conf \
		/usr/local/etc/freevrrpd.conf \
		/usr/local/etc/inc/system.inc \
		/usr/local/etc/opnsense-beep.d/freevrrpd-master \
		/usr/local/etc/rc.loader.d/25-freevrrpd \
		/usr/local/etc/rc.syshook.d/start/90-freevrrpd \
		/usr/local/etc/rc.syshook.d/stop/10-freevrrpd \
		/usr/local/libexec/freevrrpd-backup \
		/usr/local/libexec/freevrrpd-master \
		/usr/local/sbin/freevrrpd \
		/usr/local/sbin/opnsense-beep

VRRP_PRIORITY ?= 200 # not 255!

/boot/loader.conf : /usr/local/etc/rc.loader.d/25-freevrrpd
	/usr/local/etc/rc.loader
/usr/local/etc/freevrrpd.conf : /usr/local/libexec/freevrrpd-backup /usr/local/libexec/freevrrpd-master share/freevrrpd.conf
	sprg=`configctl interface address | jq -r '[.wan[] | select(.family == "inet")] | first | ("s/@@device@@/" + .device + "/; s/@@address@@/" + ((.address / ".")[0:3] | join(".")) + ".7/")'`; \
		sed -E -e "$$sprg" -e "s/@@priority@@/$(VRRP_PRIORITY)/" <share/freevrrpd.conf >$@
/usr/local/etc/inc/system.inc : Makefile share/system.inc.patch
	if grep -qF "'/sbin/kldload" $@; then patch -d / -p1 <share/system.inc.patch; fi
/usr/local/etc/opnsense-beep.d/freevrrpd-master : share/opnsense-beep.freevrrpd-master
	cp share/opnsense-beep.freevrrpd-master $@
/usr/local/etc/rc.loader.d/25-freevrrpd : share/loader.freevrrpd
	cp share/loader.freevrrpd $@
/usr/local/etc/rc.syshook.d/start/90-freevrrpd : bin/syshook-freevrrpd-start
	cp bin/syshook-freevrrpd-start $@
/usr/local/etc/rc.syshook.d/stop/10-freevrrpd : bin/syshook-freevrrpd-stop
	cp bin/syshook-freevrrpd-stop $@
/usr/local/libexec/freevrrpd-backup : bin/freevrrpd-backup
	cp bin/freevrrpd-backup $@
/usr/local/libexec/freevrrpd-master : bin/freevrrpd-master /usr/local/etc/opnsense-beep.d/freevrrpd-master /usr/local/sbin/opnsense-beep
	cp bin/freevrrpd-master $@
/usr/local/sbin/freevrrpd : /usr/local/etc/pkg/repos/ip-forward.conf
	pkg install -y freevrrpd
/usr/local/sbin/opnsense-beep : share/opnsense-beep.patch
	if ! grep -qF 'flock' $@; then patch -d / -p1 <share/opnsense-beep.patch; fi

########################################################################
# `install-2tun`

# /usr/local/opnsense/service/templates/$(VENDOR)/$(APP)/ can't handle large
# configuration file and OOMs. So, here is the hack.
install-2tun : 	build \
		install-unbound \
		/usr/local/sbin/unbound-control-dns2tun \
		/usr/local/etc/rc.syshook.d/monitor/25-dns2tun \
		/usr/local/etc/rc.syshook.d/start/85-dns2tun \
		/usr/local/etc/rc.syshook.d/early/50-ip2tun \
		/var/db/aliastables/ip2tun.gz \
		/var/run/unbound-dns2tun.pid
	make -j1 /var/run/unbound.pid
	/usr/local/etc/rc.syshook.d/early/50-ip2tun

/usr/local/etc/rc.syshook.d/monitor/25-dns2tun : bin/syshook-dns2tun /usr/local/sbin/unbound-control-dns2tun
	cp bin/syshook-dns2tun $@
/usr/local/etc/rc.syshook.d/start/85-dns2tun : bin/syshook-start-dns2tun
	cp bin/syshook-start-dns2tun $@
/usr/local/sbin/unbound-control-dns2tun : bin/unbound-control-dns2tun
	cp bin/unbound-control-dns2tun $@
/usr/local/etc/unbound/dns2tun.conf : share/unbound-dns2tun.conf
	cp share/unbound-dns2tun.conf $@
/usr/local/etc/unbound/local-tlds-ipset.conf : var/unbound.rc.local-tlds-ipset.conf.gz
	cp var/unbound.rc.local-tlds-ipset.conf.gz $@.gz
	rm -f $@
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
	/usr/local/etc/rc.syshook.d/monitor/25-dns2tun

/usr/local/etc/unbound.opnsense.d/enable-dns2tun.conf : share/unbound.opnsense.enable-dns2tun.conf
	cp share/unbound.opnsense.enable-dns2tun.conf $@
/usr/local/etc/unbound.opnsense.d/forward-to-dns2tun.conf : var/unbound.opnsense.forward-to-dns2tun.conf.gz
	cp var/unbound.opnsense.forward-to-dns2tun.conf.gz $@.gz
	rm -f $@
	gunzip $@.gz
/var/run/unbound.pid : \
		/usr/local/etc/unbound.opnsense.d/enable-dns2tun.conf \
		/usr/local/etc/unbound.opnsense.d/forward-to-dns2tun.conf
	pluginctl -s unbound restart

/usr/local/etc/rc.syshook.d/early/50-ip2tun : share/ip2tun
	cp share/ip2tun $@
	chmod 755 $@
/var/db/aliastables/ip2tun.gz : var/ipv4.gz
	cp var/ipv4.gz $@

########################################################################
# `deinstall`

deinstall-2tun :
	rm -f /usr/local/etc/unbound.opnsense.d/forward-to-dns2tun.conf /usr/local/etc/unbound.opnsense.d/enable-dns2tun.conf
	pluginctl -s unbound restart

deinstall :
	make -j1 deinstall-2tun
	service unbound stop
	rm -f /usr/local/etc/unbound/dns2tun.conf /usr/local/etc/unbound/local-tlds-ipset.conf /etc/rc.conf.d/unbound
	rm -f /var/db/aliastables/ip2tun.gz /usr/local/etc/rc.syshook.d/early/50-ip2tun
