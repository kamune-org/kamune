package fingerprint

import (
	"math/rand/v2"
	"strconv"
)

// ~150 adjectives; 2 picked per pseudonym.
var adjectives = []string{
	"agile", "amber", "ancient", "angry", "azure", "bashful", "bitter",
	"blissful", "bold", "brave", "breezy", "bright", "brilliant", "brisk",
	"brittle", "bubbly", "calm", "charming", "cheerful", "chilly", "clever",
	"cloudy", "cobalt", "content", "cool", "copper", "coral", "cozy",
	"crimson", "crisp", "cunning", "curious", "damp", "daring", "deep",
	"dew", "dewy", "dim", "dreamy", "dry", "dull", "dusty", "eager",
	"emerald", "faint", "fair", "faithful", "fancy", "fast", "fearless",
	"feeble", "fierce", "fluffy", "foggy", "foolish", "fresh", "friendly",
	"frosty", "fuzzy", "gentle", "giant", "gleeful", "gloomy", "glossy",
	"golden", "graceful", "grand", "grim", "grumpy", "happy", "harsh",
	"hasty", "hollow", "humble", "humid", "hungry", "icy", "indigo",
	"ivory", "jade", "jolly", "jovial", "keen", "kind", "lavender",
	"lazy", "lilac", "lively", "lofty", "loose", "loud", "lucky",
	"maroon", "massive", "meek", "mellow", "merry", "mighty", "mild",
	"misty", "mossy", "muddy", "navy", "neat", "nervous", "nimble",
	"noble", "noisy", "odd", "olive", "pale", "peaceful", "peach",
	"pearl", "peridot", "petite", "plain", "playful", "plum", "polite",
	"prime", "proud", "pure", "quaint", "queer", "quick", "quiet",
	"rainy", "rapid", "rare", "raw", "rich", "ripe", "rough", "royal",
	"ruby", "rustic", "sage", "sapphire", "sassy", "scarce", "scarlet",
	"secure", "serene", "shallow", "sharp", "sheer", "shiny", "shrill",
	"shy", "silent", "silky", "silver", "sleepy", "slim", "slimy",
	"slow", "smart", "smooth", "sneaky", "soft", "solemn", "somber",
	"spare", "speedy", "spicy", "stale", "stark", "steady", "stealthy",
	"stern", "stiff", "stormy", "stout", "strange", "strong", "subtle",
	"sullen", "sunny", "supple", "sweet", "swift", "tame", "tan",
	"tart", "taut", "teal", "tender", "thick", "thin", "tidy",
	"tight", "tiny", "tough", "tranquil", "trim", "tropical", "true",
	"upbeat", "vast", "velvety", "vibrant", "violet", "vivid", "warm",
	"wary", "weary", "weird", "wet", "whimsical", "wild", "windy",
	"wise", "wispy", "witty", "wonderful", "woozy", "young", "youthful",
	"zany", "zealous",
}

// ~150 nouns; 1 picked per pseudonym.
var nouns = []string{
	"albatross", "alligator", "alpaca", "ant", "anteater", "armadillo",
	"badger", "barnacle", "barracuda", "bat", "bear", "beaver", "bee",
	"beetle", "bison", "boar", "bobcat", "buffalo", "butterfly", "camel",
	"caribou", "cat", "centipede", "chameleon", "cheetah", "chicken",
	"chimpanzee", "cicada", "clam", "cobra", "coral", "cougar", "cow",
	"coyote", "crab", "crane", "cricket", "crocodile", "crow", "deer",
	"dingo", "dog", "dolphin", "donkey", "dragon", "duck", "eagle", "eel",
	"elk", "falcon", "ferret", "fish", "flamingo", "fox", "frog", "gazelle",
	"gecko", "gibbon", "giraffe", "goat", "goose", "gopher", "gorilla",
	"grasshopper", "gull", "hamster", "hawk", "heron", "hippo", "hornet",
	"horse", "hummingbird", "ibex", "iguana", "impala", "jackal", "jaguar",
	"jellyfish", "kangaroo", "koala", "lemur", "leopard", "lion", "lizard",
	"llama", "lobster", "lynx", "magpie", "manatee", "mandrill", "marten",
	"mink", "mole", "mongoose", "monkey", "moose", "mouse", "newt",
	"ocelot", "octopus", "opossum", "orangutan", "orca", "ostrich", "otter",
	"owl", "ox", "panda", "panther", "parrot", "peacock", "pelican",
	"penguin", "pig", "pigeon", "platypus", "pony", "porcupine", "puma",
	"python", "rabbit", "raccoon", "rat", "raven", "reindeer", "rhino",
	"rooster", "salamander", "salmon", "scallop", "scorpion", "seahorse",
	"seal", "serval", "shark", "sheep", "shrew", "shrimp", "skunk",
	"sloth", "snail", "snake", "sparrow", "spider", "squid", "squirrel",
	"stingray", "stork", "swan", "tapir", "tarantula", "termite", "tiger",
	"toad", "toucan", "turkey", "turtle", "viper", "vulture", "walrus",
	"wasp", "weasel", "weevil", "whale", "wolf", "wolverine", "wombat",
	"woodpecker", "worm", "yak", "zebra",
}

// Pseudonym returns a random human-readable name of the form
// "<adjective> <adjective> <noun> <1-99>".
//
// With ~150 adjectives, ~150 nouns, and 99 possible suffixes,
// there are roughly 150 × 150 × 150 × 99 ≈ 334 million combinations.
func Pseudonym() string {
	adj1 := adjectives[rand.IntN(len(adjectives))]
	adj2 := adjectives[rand.IntN(len(adjectives))]
	noun := nouns[rand.IntN(len(nouns))]
	num := rand.IntN(99) + 1
	return adj1 + " " + adj2 + " " + noun + " " + strconv.Itoa(num)
}
