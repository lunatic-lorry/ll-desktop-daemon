#![forbid(unsafe_code)]

const I32: u8 = 0x7f;
const I64: u8 = 0x7e;

#[derive(Clone, Copy)]
struct ExpectedImport {
    module: &'static str,
    name: &'static str,
    params: &'static [u8],
    results: &'static [u8],
}

const ALLOWED_IMPORTS: &[ExpectedImport] = &[
    ExpectedImport {
        module: "lunatic::message",
        name: "receive",
        params: &[I32, I32, I64],
        results: &[I32],
    },
    ExpectedImport {
        module: "lunatic::message",
        name: "read_data",
        params: &[I32, I32],
        results: &[I32],
    },
    ExpectedImport {
        module: "lunatic::message",
        name: "get_tag",
        params: &[],
        results: &[I64],
    },
    ExpectedImport {
        module: "lunatic::message",
        name: "get_process_id",
        params: &[],
        results: &[I64],
    },
    // Rust's WASI startup currently probes the environment. The daemon's
    // DefaultProcessConfig supplies zero environment variables, so these calls
    // expose no ambient values; any future WASI import still fails closed.
    ExpectedImport {
        module: "wasi_snapshot_preview1",
        name: "environ_get",
        params: &[I32, I32],
        results: &[I32],
    },
    ExpectedImport {
        module: "wasi_snapshot_preview1",
        name: "environ_sizes_get",
        params: &[I32, I32],
        results: &[I32],
    },
    ExpectedImport {
        module: "wasi_snapshot_preview1",
        name: "fd_write",
        params: &[I32, I32, I32, I32],
        results: &[I32],
    },
    ExpectedImport {
        module: "wasi_snapshot_preview1",
        name: "proc_exit",
        params: &[I32],
        results: &[],
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct FunctionType {
    params: Vec<u8>,
    results: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FunctionImport {
    module: String,
    name: String,
    type_index: u32,
}

fn read_leb_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut value = 0u32;
    let mut shift = 0u32;
    loop {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| "unexpected EOF while reading LEB128".to_owned())?;
        *cursor += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 35 {
            return Err("invalid u32 LEB128".to_owned());
        }
    }
}

fn read_name<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a str, String> {
    let len = usize::try_from(read_leb_u32(bytes, cursor)?)
        .map_err(|_| "WASM name length does not fit usize".to_owned())?;
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| "WASM name length overflow".to_owned())?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or_else(|| "unexpected EOF while reading WASM name".to_owned())?;
    *cursor = end;
    return std::str::from_utf8(raw).map_err(|_| "WASM import name is not UTF-8".to_owned());
}

fn read_valtypes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
    let count = usize::try_from(read_leb_u32(bytes, cursor)?)
        .map_err(|_| "value-type count does not fit usize".to_owned())?;
    let end = cursor
        .checked_add(count)
        .ok_or_else(|| "value-type count overflow".to_owned())?;
    let values = bytes
        .get(*cursor..end)
        .ok_or_else(|| "unexpected EOF while reading value types".to_owned())?
        .to_vec();
    *cursor = end;
    return Ok(values);
}

fn parse_types(
    bytes: &[u8],
    cursor: &mut usize,
    section_end: usize,
) -> Result<Vec<FunctionType>, String> {
    let count = read_leb_u32(bytes, cursor)?;
    let mut types = Vec::new();
    for _ in 0..count {
        let marker = *bytes
            .get(*cursor)
            .ok_or_else(|| "missing function type marker".to_owned())?;
        *cursor += 1;
        if marker != 0x60 {
            return Err(format!(
                "unsupported non-function type marker 0x{marker:02x}"
            ));
        }
        types.push(FunctionType {
            params: read_valtypes(bytes, cursor)?,
            results: read_valtypes(bytes, cursor)?,
        });
    }
    if *cursor != section_end {
        return Err("type section parser did not consume the exact section".to_owned());
    }
    return Ok(types);
}

fn parse_imports(
    bytes: &[u8],
    cursor: &mut usize,
    section_end: usize,
) -> Result<Vec<FunctionImport>, String> {
    let count = read_leb_u32(bytes, cursor)?;
    let mut imports = Vec::new();
    for _ in 0..count {
        let module = read_name(bytes, cursor)?.to_owned();
        let name = read_name(bytes, cursor)?.to_owned();
        let kind = *bytes
            .get(*cursor)
            .ok_or_else(|| "missing import kind".to_owned())?;
        *cursor += 1;
        if kind != 0 {
            return Err(format!(
                "non-function import {module}.{name} has unsupported kind {kind}; Lambda imports must be explicit functions"
            ));
        }
        imports.push(FunctionImport {
            module,
            name,
            type_index: read_leb_u32(bytes, cursor)?,
        });
    }
    if *cursor != section_end {
        return Err("import section parser did not consume the exact section".to_owned());
    }
    return Ok(imports);
}

fn module_contract(bytes: &[u8]) -> Result<(Vec<FunctionType>, Vec<FunctionImport>), String> {
    if !bytes.starts_with(b"\0asm\x01\0\0\0") {
        return Err("not a WebAssembly v1 module".to_owned());
    }
    let mut cursor = 8usize;
    let mut types = Vec::new();
    let mut imports = Vec::new();
    while cursor < bytes.len() {
        let section_id = *bytes
            .get(cursor)
            .ok_or_else(|| "missing section id".to_owned())?;
        cursor += 1;
        let section_len = usize::try_from(read_leb_u32(bytes, &mut cursor)?)
            .map_err(|_| "section length does not fit usize".to_owned())?;
        let section_end = cursor
            .checked_add(section_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| "section extends past end of module".to_owned())?;
        match section_id {
            1 => {
                types = parse_types(bytes, &mut cursor, section_end)?;
            }
            2 => {
                imports = parse_imports(bytes, &mut cursor, section_end)?;
            }
            _ => {
                cursor = section_end;
            }
        }
    }
    return Ok((types, imports));
}

pub(crate) fn validate_lunatic_lambda_imports(bytes: &[u8]) -> Result<(), String> {
    let (types, imports) = module_contract(bytes)?;
    for import in imports {
        let function_type = types
            .get(
                usize::try_from(import.type_index)
                    .map_err(|_| "type index does not fit usize".to_owned())?,
            )
            .ok_or_else(|| {
                format!(
                    "import {}.{} references missing function type {}",
                    import.module, import.name, import.type_index
                )
            })?;
        let Some(expected) = ALLOWED_IMPORTS
            .iter()
            .find(|expected| expected.module == import.module && expected.name == import.name)
        else {
            return Err(format!(
                "Lunatic Lambda import is outside the reviewed capability allowlist: {}.{}",
                import.module, import.name
            ));
        };
        if function_type.params != expected.params || function_type.results != expected.results {
            return Err(format!(
                "Lunatic Lambda import {}.{} has an unexpected function signature",
                import.module, import.name
            ));
        }
    }
    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_wasm() {
        assert!(validate_lunatic_lambda_imports(b"not wasm").is_err());
    }

    #[test]
    fn minimal_wasm_without_imports_is_admitted() {
        assert!(validate_lunatic_lambda_imports(b"\0asm\x01\0\0\0").is_ok());
    }

    #[test]
    fn forbidden_network_import_fails_closed() {
        let wasm = b"\0asm\x01\0\0\0\x01\x04\x01\x60\x00\x00\x02\x1f\x01\x13lunatic::networking\x0btcp_connect\x00\x00";
        assert!(validate_lunatic_lambda_imports(wasm).is_err());
    }
}
