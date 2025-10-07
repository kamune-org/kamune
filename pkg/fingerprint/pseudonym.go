package fingerprint

import (
	"math/rand/v2"
)

var adjectives = []string{
	"agile", "ancient", "angry", "bashful", "bold", "brave", "bright",
	"calm", "clever", "curious", "daring", "eager", "fancy", "fast",
	"fierce", "fuzzy", "gentle", "giant", "happy", "hungry", "jolly",
	"lazy", "lively", "lucky", "mighty", "nervous", "noisy", "peaceful",
	"playful", "proud", "quiet", "quick", "rapid", "rare", "restless",
	"sassy", "shiny", "shy", "silent", "sleepy", "smart", "sneaky",
	"speedy", "spicy", "stealthy", "strong", "sweet", "swift",
	"tiny", "tough", "vivid", "wild", "wise", "zany",
}

var nouns = []string{
	"ant", "badger", "bat", "bear", "beaver", "bee", "bison", "boar",
	"buffalo", "camel", "cat", "chicken", "cobra", "cougar", "cow",
	"crab", "crane", "crocodile", "crow", "deer", "dog", "dolphin",
	"donkey", "dragon", "duck", "eagle", "falcon", "ferret", "fish",
	"fox", "frog", "goat", "goose", "hamster", "hawk", "hippo", "horse",
	"jackal", "jaguar", "kangaroo", "koala", "leopard", "lion",
	"lizard", "llama", "monkey", "moose", "mouse", "octopus",
	"otter", "owl", "ox", "panda", "panther", "parrot", "penguin",
	"pig", "pigeon", "rabbit", "raccoon", "rat", "raven", "seal",
	"shark", "sheep", "sloth", "snake", "sparrow", "squid", "swan",
	"tiger", "turkey", "turtle", "weasel", "whale", "wolf", "zebra",
}

func Pseudonym() string {
	adj := adjectives[rand.IntN(len(adjectives))]
	noun := nouns[rand.IntN(len(nouns))]
	return adj + " " + noun
}
