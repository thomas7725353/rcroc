use rand::Rng;

const WORDS: &[&str] = &[
    "acorn", "amber", "anchor", "april", "arrow", "atlas", "basil", "beacon", "birch", "breeze",
    "brook", "cactus", "cinder", "clover", "cobalt", "comet", "coral", "crane", "daisy", "delta",
    "ember", "falcon", "fern", "fjord", "flint", "forest", "frost", "glade", "granite", "harbor",
    "hazel", "hollow", "indigo", "iris", "jade", "juniper", "kestrel", "lagoon", "lantern",
    "maple", "meadow", "moss", "nectar", "onyx", "opal", "orchid", "pebble", "pine", "prairie",
    "quartz", "raven", "ridge", "river", "sable", "sierra", "spruce", "stone", "timber", "topaz",
    "valley", "willow", "zephyr",
];

pub fn generate_secret() -> String {
    let mut rng = rand::thread_rng();
    let pin: u16 = rng.gen_range(0..10_000);
    let w1 = WORDS[rng.gen_range(0..WORDS.len())];
    let w2 = WORDS[rng.gen_range(0..WORDS.len())];
    let w3 = WORDS[rng.gen_range(0..WORDS.len())];
    format!("{:04}-{}-{}-{}", pin, w1, w2, w3)
}
