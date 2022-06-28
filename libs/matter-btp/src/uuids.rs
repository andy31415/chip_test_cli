pub mod characteristics {
    use uuid::Uuid;

    pub const WRITE: Uuid = Uuid::from_u128(0x18EE2EF5_263D_4559_959F_4F9C429F9D11);
    pub const READ: Uuid = Uuid::from_u128(0x18EE2EF5_263D_4559_959F_4F9C429F9D12);
    pub const COMMISSIONING_DATA: Uuid = Uuid::from_u128(0x64630238_8772_45F2_B87D_748A83218F04);
}

pub mod services {
    use uuid::Uuid;

    pub const MATTER: Uuid = Uuid::from_u128(0x0000FFF6_0000_1000_8000_00805F9B34FB);
}
