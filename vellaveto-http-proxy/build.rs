fn main() {
    #[cfg(feature = "grpc")]
    {
        let proto_file = "../proto/mcp/v1/mcp.proto";
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            .compile_protos(&[proto_file], &["../proto"])
            .expect("Failed to compile MCP protobuf schema");
    }
}
