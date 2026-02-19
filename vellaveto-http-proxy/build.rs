fn main() {
    #[cfg(feature = "grpc")]
    {
        let proto_file = "../proto/mcp/v1/mcp.proto";
        if let Err(error) = tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            .compile_protos(&[proto_file], &["../proto"])
        {
            eprintln!("Failed to compile MCP protobuf schema: {error}");
            std::process::exit(1);
        }
    }
}
