use bitcoin::bip32;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub enum Wildcard {
    None,
    Unhardened,
    Hardened,
}

#[derive(Debug, Clone)]
pub struct ParseError(&'static str);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error while parsing policy: {}", self.0)
    }
}

/// from https://github.com/rust-bitcoin/rust-miniscript/blob/master/src/descriptor/key.rs#L780
pub fn parse_xkey_deriv(
    key_deriv: &str,
) -> Result<(Vec<bip32::DerivationPath>, Wildcard), ParseError> {
    let mut wildcard = Wildcard::None;
    let mut multipath = false;
    let derivation_paths = key_deriv
        .replace("**", "<0;1>/*")
        .split('/')
        .filter_map(|p| {
            if wildcard == Wildcard::None && p == "*" {
                wildcard = Wildcard::Unhardened;
                None
            } else if wildcard == Wildcard::None && (p == "*'" || p == "*h") {
                wildcard = Wildcard::Hardened;
                None
            } else if wildcard != Wildcard::None {
                Some(Err(ParseError(
                    "'*' may only appear as last element in a derivation path.",
                )))
            } else {
                // BIP389 defines a new step in the derivation path. This step contains two or more
                // derivation indexes in the form '<1;2;3';4h;5H;6>'.
                if p.starts_with('<') && p.ends_with('>') {
                    // There may only be one occurence of this step.
                    if multipath {
                        return Some(Err(ParseError(
                            "'<' may only appear once in a derivation path.",
                        )));
                    }
                    multipath = true;

                    // The step must contain at least two derivation indexes.
                    // So it's at least '<' + a number + ';' + a number + '>'.
                    if p.len() < 5 || !p.contains(';') {
                        return Some(Err(ParseError(
                            "Invalid multi index step in multipath descriptor.",
                        )));
                    }

                    // Collect all derivation indexes at this step.
                    let indexes = p[1..p.len() - 1].split(';');
                    Some(
                        indexes
                            .into_iter()
                            .map(|s| {
                                bip32::ChildNumber::from_str(s).map_err(|_| {
                                    ParseError("Error while parsing index in key derivation path.")
                                })
                            })
                            .collect::<Result<Vec<bip32::ChildNumber>, _>>(),
                    )
                } else {
                    // Not a BIP389 step, just a regular derivation index.
                    Some(
                        bip32::ChildNumber::from_str(p)
                            .map(|i| vec![i])
                            .map_err(|_| ParseError("Error while parsing key derivation path")),
                    )
                }
            }
        })
        // Now we've got all derivation indexes in a list of vectors of indexes. If the derivation
        // path was empty then this list is empty. If the derivation path didn't contain any BIP389
        // step all the vectors of indexes contain a single element. If it did though, one of the
        // vectors contains more than one element.
        // Now transform this list of vectors of steps into distinct derivation paths.
        .try_fold(Vec::new(), |mut paths, index_list| {
            let mut index_list = index_list?.into_iter();
            let first_index = index_list
                .next()
                .expect("There is always at least one element");

            if paths.is_empty() {
                paths.push(vec![first_index]);
            } else {
                for path in paths.iter_mut() {
                    path.push(first_index);
                }
            }

            // If the step is a BIP389 one, create as many paths as there is indexes.
            for (i, index) in index_list.enumerate() {
                paths.push(paths[0].clone());
                *paths[i + 1].last_mut().expect("Never empty") = index;
            }

            Ok(paths)
        })?
        .into_iter()
        .map(|index_list| index_list.into_iter().collect::<bip32::DerivationPath>())
        .collect::<Vec<bip32::DerivationPath>>();

    Ok((derivation_paths, wildcard))
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_xkey_deriv() {
        // We can have a key in a descriptor that has multiple paths
        let (paths, wildcard) = parse_xkey_deriv("2/<0;1;42;9854>").unwrap();
        assert_eq!(wildcard, Wildcard::None);
        assert_eq!(
            paths,
            vec![
                bip32::DerivationPath::from_str("m/2/0").unwrap(),
                bip32::DerivationPath::from_str("m/2/1").unwrap(),
                bip32::DerivationPath::from_str("m/2/42").unwrap(),
                bip32::DerivationPath::from_str("m/2/9854").unwrap()
            ],
        );

        // Even if it's in the middle of the derivation path.
        let (paths, wildcard) = parse_xkey_deriv("2/<0;1;9854>/0/5/10").unwrap();
        assert_eq!(wildcard, Wildcard::None);
        assert_eq!(
            paths,
            vec![
                bip32::DerivationPath::from_str("m/2/0/0/5/10").unwrap(),
                bip32::DerivationPath::from_str("m/2/1/0/5/10").unwrap(),
                bip32::DerivationPath::from_str("m/2/9854/0/5/10").unwrap()
            ],
        );

        // Even if it is a wildcard extended key.
        let (paths, wildcard) = parse_xkey_deriv("2/<0;1;9854>/3456/9876/*").unwrap();
        assert_eq!(wildcard, Wildcard::Unhardened);
        assert_eq!(
            paths,
            vec![
                bip32::DerivationPath::from_str("m/2/0/3456/9876").unwrap(),
                bip32::DerivationPath::from_str("m/2/1/3456/9876").unwrap(),
                bip32::DerivationPath::from_str("m/2/9854/3456/9876").unwrap()
            ],
        );

        // Also even if it has an origin.
        let (paths, wildcard) = parse_xkey_deriv("<0;1>/*").unwrap();
        assert_eq!(wildcard, Wildcard::Unhardened);
        assert_eq!(
            paths,
            vec![
                bip32::DerivationPath::from_str("m/0").unwrap(),
                bip32::DerivationPath::from_str("m/1").unwrap(),
            ],
        );

        // Also if it has hardened steps in the derivation path. In fact, it can also have hardened
        // indexes even at the step with multiple indexes!
        let (paths, wildcard) = parse_xkey_deriv("9478'/<0';1h>/8h/*'").unwrap();
        assert_eq!(wildcard, Wildcard::Hardened);
        assert_eq!(
            paths,
            vec![
                bip32::DerivationPath::from_str("m/9478'/0'/8'").unwrap(),
                bip32::DerivationPath::from_str("m/9478h/1h/8h").unwrap(),
            ],
        );

        // It's invalid to:
        // - Not have opening or closing brackets
        // - Have multiple steps with different indexes
        // - Only have one index within the brackets
        parse_xkey_deriv("2/<0;1;42;9854").unwrap_err();
        parse_xkey_deriv("2/0;1;42;9854>").unwrap_err();
        parse_xkey_deriv("2/4/<0;1>/96/<0;1>").unwrap_err();
        parse_xkey_deriv("2/4/<0>").unwrap_err();
        parse_xkey_deriv("2/4/<0;>").unwrap_err();
        parse_xkey_deriv("2/4/<;1>").unwrap_err();
        parse_xkey_deriv("2/4/<0;1;>").unwrap_err();
    }
}
