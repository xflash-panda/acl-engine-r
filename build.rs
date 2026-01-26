use std::io::Result;

fn main() -> Result<()> {
    // Compile protobuf definitions
    prost_build::compile_protos(&["src/geo/dat/geodat.proto"], &["src/geo/dat/"])?;
    Ok(())
}
