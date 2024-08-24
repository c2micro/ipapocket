from ipapocket.krb5.types.ticket import Ticket
from ipapocket.krb5.asn1 import TicketsAsn1


class Tickets:
    _tickets: list[Ticket] = list[Ticket]()

    def __init__(self):
        self.clear()

    def add(self, ticket):
        self._tickets.append(Ticket.load(ticket))

    def clear(self):
        self._tickets = list()

    @property
    def tickets(self) -> list[Ticket]:
        return self._tickets

    @classmethod
    def load(cls, data: TicketsAsn1):
        if isinstance(data, bytes):
            data = TicketsAsn1.load(data)
        if isinstance(data, Tickets):
            data = data.to_asn1()
        tmp = cls()
        for v in data:
            tmp.add(Ticket.load(v))
        return tmp

    def to_asn1(self) -> TicketsAsn1:
        tmp = list()
        for ticket in self.tickets:
            tmp.append(ticket.to_asn1())
        return TicketsAsn1(tuple(tmp))

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
