use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() {
    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("codegen.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());
    let mut m: phf_codegen::OrderedMap<&'static str> = phf_codegen::OrderedMap::new();
    let counter: usize = 0;

    #[cfg(feature = "tag")]
    let m = m.entry(
        "tag",
        format!("({}usize, {}usize)", counter, counter + 16).as_str(),
    );
    #[cfg(feature = "tag")]
    let counter = counter + 16;

    #[cfg(feature = "sport")]
    let m = m.entry(
        "sport",
        format!("({}usize, {}usize)", counter, counter + 16).as_str(),
    );
    #[cfg(feature = "sport")]
    let counter = counter + 16;

    #[cfg(feature = "dport")]
    let m = m.entry(
        "dport",
        format!("({}usize, {}usize)", counter, counter + 16).as_str(),
    );
    #[cfg(feature = "dport")]
    let counter = counter + 16;

    #[cfg(feature = "sip")]
    let m = m.entry(
        "sip",
        format!("({}usize, {}usize)", counter, counter + 32).as_str(),
    );
    #[cfg(feature = "sip")]
    let counter = counter + 32;

    #[cfg(feature = "dip")]
    let m = m.entry(
        "dip",
        format!("({}usize, {}usize)", counter, counter + 32).as_str(),
    );
    #[cfg(feature = "dip")]
    let counter = counter + 32;

    write!(
        &mut file,
        "pub static FIELD_MAP: phf::OrderedMap<&'static str, (usize, usize)> = {}",
        m.build()
    )
    .unwrap();
    writeln!(&mut file, ";\n").unwrap();
    writeln!(&mut file, "pub const MAX_POS: usize = {}usize;\n", counter).unwrap();
}
