
#[non_exhaustive]
pub struct Ethertypes;

impl Ethertypes {
    pub const IPV4 : u16            = 0x0800;
    pub const ARP : u16             = 0x0806;
    pub const IEEE_8021Q : u16      = 0x8100;
    pub const IPV6 : u16            = 0x86DD;

    pub fn has_l3(ethertype : u16) -> bool {
        return (ethertype == Ethertypes::IPV4) ||
               (ethertype == Ethertypes::IPV6) ||
               (ethertype == Ethertypes::IEEE_8021Q);
    }
}
