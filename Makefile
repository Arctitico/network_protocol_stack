all: common ethernet arp icmp ip udp

common ethernet arp icmp ip udp:
	@$(MAKE) -C $@

web:
	@$(MAKE) -C web

clean:
	@for dir in common ethernet arp icmp ip udp; do $(MAKE) -C $$dir clean; done

.PHONY: all common ethernet arp icmp ip udp web clean
