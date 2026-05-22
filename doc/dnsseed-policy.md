Expectations for zkCoin DNS seed operators
==========================================

zkCoin Core attempts to minimize the level of trust in DNS seeds, but DNS
seeds still pose a small amount of risk for the network. Public DNS seed
infrastructure must therefore be operated by entities that have an explicit
operational relationship with the zkCoin launch process.

Until zkCoin-specific seed infrastructure exists, public `main` and `testnet`
startup remains fail-closed. Inherited Litecoin DNS seed data, crawlers, or
compiled seed lists must not be used as zkCoin public-network launch inputs.

0. A DNS seed operating organization or person is expected to follow good host
security practices, maintain control of applicable infrastructure, and not sell
or transfer control of the DNS seed. Any hosting services contracted by the
operator are equally expected to uphold these expectations.

1. The DNS seed results must consist exclusively of fairly selected and
functioning zkCoin nodes from the intended zkCoin public network to the best of
the operator's understanding and capability.

2. For the avoidance of doubt, the results may be randomized but must not
single out any group of hosts to receive different results unless due to an
urgent technical necessity and disclosed.

3. The results may not be served with a DNS TTL of less than one minute.

4. Any logging of DNS queries should be only that which is necessary for the
operation of the service or urgent health of the zkCoin network and must not be
retained longer than necessary nor disclosed to any third party.

5. Information gathered as a result of the operator's node-spidering, not from
DNS queries, may be freely published or retained, but only if this data was not
made more complete by biasing node connectivity, which would violate
expectation 1.

6. Operators are encouraged, but not required, to publicly document the details
of their operating practices.

7. A reachable email contact address must be published for inquiries related to
the DNS seed operation.

If these expectations cannot be satisfied, the operator should discontinue
providing services and contact the active zkCoin maintainers.

Behavior outside of these expectations may be reasonable in some situations but
should be discussed in public in advance.

See also
--------
- A zkCoin seed source must be generated from zkCoin public-network crawler
  output before DNS seeds or fixed seeds can be considered production-ready.
