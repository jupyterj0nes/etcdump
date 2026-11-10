//! Measuring the rules on clean reference evidence: `etcdump --measure`.
//!
//! The inputs are taken as stock, clean Linux hosts. Every rule is run over every item they
//! hold; `rarity.tsv` gets, per rule, how many items it fired on, how many items there
//! were and the points that rarity is worth (`-10 · log10(hits / items)`, the bound
//! `-10 · log10(1 / (items + 1))` for a rule that never fired); `reference.tsv` gets every
//! item a rule fired on, so the same item elsewhere is `habitual`. The two files written
//! into `src/builtin/` are what the binary ships.

use std::collections::BTreeMap;
use std::path::Path;

use crate::rules::{self, RuleSet};
use crate::run::{self, Options};

pub mod code {
    crate::codes! {
        MEASURE_STARTED = 650, "measuring the rules on the inputs, taken as clean reference evidence (shown with -v)";
        MEASURE_NO_ITEMS = 651, "the reference inputs gave no configuration item: nothing can be measured (is there a Linux root in them?)";
        MEASURE_WRITTEN = 652, "rarity.tsv and reference.tsv were written into the output folder; copy them into src/builtin/ to ship them";
        MEASURE_WRITE_FAILED = 653, "rarity.tsv or reference.tsv could not be written";
        MEASURE_RULE_NOISE = 654, "a rule fires on more than one reference item in ten (below 10 points): it is noise on stock hosts and gives neither state nor points";
        MEASURE_FILTERED = 655, "--measure ignores the filters (--grep, --area, --since, --until, --only-hunted): a measurement needs every item";
    }
}

/// The two tables, as text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tables {
    pub rarity: String,
    pub reference: String,
    pub items: u64,
}

/// Runs the rules over the inputs and builds the tables.
pub fn measure(opts: &Options) -> crate::diag::Result<Tables> {
    crate::diag::info(code::MEASURE_STARTED, format!("{} input(s)", opts.inputs.len()));
    let mut o = opts.clone();
    if !o.filter.is_empty() {
        crate::diag::warn(code::MEASURE_FILTERED, "filters ignored");
        o.filter = Default::default();
    }
    o.no_hunt = true;
    let outcome = run::run(&o, &|_, _, _| {})?;
    let set = RuleSet::load(!opts.no_builtin_rules, &opts.rules, &[]);
    let mut hits: BTreeMap<String, u64> = set.rules.iter().map(|r| (r.name.clone(), 0)).collect();
    let mut reference: Vec<String> = Vec::new();
    let mut items = 0u64;
    for f in &outcome.files {
        for (it, _) in &f.items {
            items += 1;
            for r in &set.rules {
                if r.matches(f.cf.area, &f.cf.rel, it) {
                    *hits.entry(r.name.clone()).or_default() += 1;
                    reference.push(format!("{}\t{}\t{}\t{}\t{}", r.name, f.cf.area, rules::tsv(&f.cf.rel), rules::tsv(&it.key), rules::tsv(&it.value)));
                }
            }
        }
    }
    if items == 0 {
        return Err(crate::diag::fail(code::MEASURE_NO_ITEMS, format!("{} input(s)", opts.inputs.len())));
    }
    reference.sort();
    reference.dedup();
    let names: Vec<String> = outcome.items_read.iter().map(|i| i.1.clone()).collect();
    let mut rarity = format!("# rule\thits\titems\tpoints — measured by etcdump --measure on {} ({items} items)\n", names.join(", "));
    for (name, h) in &hits {
        let p = rules::points(*h, items);
        if p < 10 {
            crate::diag::warn(code::MEASURE_RULE_NOISE, format!("{name}: {h} of {items}"));
        }
        rarity.push_str(&format!("{name}\t{h}\t{items}\t{p}\n"));
    }
    let mut refs = format!("# rule\tarea\tpath\tkey\tvalue — items of {} on which a rule fired\n", names.join(", "));
    for l in reference {
        refs.push_str(&l);
        refs.push('\n');
    }
    Ok(Tables { rarity, reference: refs, items })
}

/// Writes the tables into a folder.
pub fn write(dir: &Path, t: &Tables) -> crate::diag::Result<()> {
    crate::output::prepare_dir(dir)?;
    for (name, text) in [("rarity.tsv", &t.rarity), ("reference.tsv", &t.reference)] {
        std::fs::write(dir.join(name), text).map_err(|e| crate::diag::fail(code::MEASURE_WRITE_FAILED, format!("{name}: {e}")))?;
    }
    crate::diag::info(code::MEASURE_WRITTEN, dir.display().to_string());
    Ok(())
}
