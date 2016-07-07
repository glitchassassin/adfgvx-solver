from functools import partial
import sys
from multiprocessing import Pool
import collections
import re
import operator
import math
import itertools
import random
from ngram_score import ngram_score
from pycipher import SimpleSubstitution as SimpleSub

# Global Constants

KEY_LENGTH = 5
MAX_ICS = 40
SUB_ROUNDS = 20

def main():
	ciphertext = "DGDAF FAFDA DGDVG AFAFV ADGVF DAGDF GDADA AVAAV GAGDD AGGAA AFAGG ADDFG VFGAA FDGAF GAFFF VDAGX DAGAF VVDAA DGDVD GFAFA ADFGF AADFF VAGVG VFAVV AVGVG ADFFG FVDAA VAVAG AFADA XFDAA FXGAA GXAVV DVAGD XADAV FGAAF GAGGD GGAGF AFDAG DAGVA FVGXX"
	
	# Assuming ADFGVX cipher. Two steps to encode - fractionate (digraph for 
	# each letter) and then transpose (rearrange columns based on a key).
	
	# To crack, we brute-force the transposition until the digraph frequency 
	# analysis resembles English.

	# Strip spaces/unnecessary characters:
	ciphertext = re.sub(r'[^A-Z]+', '', ciphertext)
	possible_matches = {}
	
	# Clear output file
	outfile = open("output.txt", "w")
	outfile.close()
	
	print "Ciphertext is {} characters in length.".format(len(ciphertext))
	print ciphertext + "\n\n"
	
	print "Evaluating key length {}".format(KEY_LENGTH)
	
	# Split the message into columns:
	column_length = int(math.floor(len(ciphertext) / KEY_LENGTH))
	columns = [ciphertext[i:i+column_length] for i in range(0, len(ciphertext), column_length)]
	
	
	# Try rearranging the columns and check the Index of Coincidence, keeping the top 40 results.

	pool = Pool(processes=4)
	transpose_perms = itertools.permutations(range(0,KEY_LENGTH))
	map_function = partial(permute_and_check_columns, columns)
	for match in pool.imap(map_function, transpose_perms):
		if match is not None and (len(possible_matches) < MAX_ICS or match["ic"] > min(possible_matches.keys())): # This IC is bigger than the smallest
			if match["ic_key"] not in possible_matches:
				if len(possible_matches) == MAX_ICS:
					del possible_matches[min(possible_matches.keys())] # Remove the smallest IC to make room for the new one
				print " > Possible unique match found (IC_Key): {} [{}]".format(match["ic_key"], ",".join([str(x) for x in match["transpose"]]))
				dump_match(match)
				possible_matches[match["ic_key"]] = match
	print "\n"
	
	print "Identified {} unique IC keys. Only {} potential {}-character transposition keys.\n".format(len(possible_matches), len(possible_matches) * math.factorial(KEY_LENGTH/2), KEY_LENGTH)
	# Save IC analysis
	matchfile = open('matches.txt', 'w')
	matchfile.write(str(possible_matches))
	matchfile.close()

	#print "Max IC found: {}".format(max(possible_matches.keys()))
	#return 0

	print "      [ Checking transposition keys... ] "
	
	#possible_matches = eval(open('matches.txt', 'r').read())
	max_fitness = -99e9
	max_trans_key = ""
	max_sub_key = ""
	max_plaintext = ""
	potential_keys = generate_potential_keys(possible_matches)
	map_function = partial(permute_and_decipher, columns)
	for results in pool.imap(map_function, potential_keys):
		fitness, trans_key, sub_key, plaintext = results
		if fitness > max_fitness:
			max_fitness = fitness
			max_trans_key = trans_key
			max_sub_key = sub_key
			max_plaintext = plaintext
			print "Better solution found (fitness score {}):".format(max_fitness)
			print "   Transposition key: ({})".format(max_trans_key)
			print "   Substitution key: {}".format(max_sub_key)
			print "   Plaintext: \n{}\n\n".format(max_plaintext)
			outfile = open("output.txt", "a")
			outfile.write("Better solution found (fitness score {}):\n".format(max_fitness))
			outfile.write("   Transposition key: ({})\n".format(max_trans_key))
			outfile.write("   Substitution key: {}\n".format(max_sub_key))
			outfile.write("   Plaintext: \n{}\n\n".format(max_plaintext))
			outfile.close()
	return 0

def permute_and_decipher(columns, trans_key):
	unscrambled = digraph_decompose(stitch_columns(permute_columns(trans_key, columns)))
	# Calculate monoalphabetic cipher solution
	fitness, sub_key, plaintext = test_substitution_cipher(unscrambled, SUB_ROUNDS)
	return (fitness, trans_key, sub_key, plaintext)

def permute_and_check_columns(columns, transpose_key):
	match = None

	perm_columns = permute_columns(transpose_key, columns)
	stitched_columns = stitch_columns(perm_columns)
	decomposed = digraph_decompose(stitched_columns)
	ic = index_of_coincidence(decomposed)
	ic_key = "{:f}".format(ic)
	match = {
		"ic": ic,
		"ic_key": ic_key,
		"columns": perm_columns,
		"transpose": transpose_key,
		"decomposed": digraph_decompose(stitched_columns)
	}
	return match

def generate_potential_keys(matches):
	potential_keys = []
	match_keys = matches.keys()
	match_keys.sort(reverse=True)
	for match in match_keys:
		for transpose_key in itertools.permutations(range(0,int(math.ceil(len(matches[match]["transpose"])/2.0)))):
			potential_key = []
			for i in transpose_key:
				potential_key.extend(matches[match]["transpose"][i*2:i*2+2])
			if potential_key not in potential_keys:
				potential_keys.append(potential_key)
	return potential_keys
	
def permute_columns(permutation, columns):
	# Permutation is a list [0,1,2...n] where n is len(columns)
	# in a particular order. Rearrange columns accordingly
	permuted = [columns[x] for x in permutation]
	return permuted
	
def dump_match(match):
	outfile = open("output.txt", "a")
	outfile.write("Possible match (IC: {}):\n".format(match["ic"]))
	outfile.write("Transpose key: ({})\n".format(",".join([str(x) for x in match["transpose"]])))
	outfile.write(stitch_columns(match["columns"]) + "\n")
	outfile.write("Decomposed [{}-char alphabet]:\n".format(len(set(match["decomposed"]))))
	outfile.write(match["decomposed"] + "\n\n")
	outfile.close()
	
def stitch_columns(columns):
	#return "".join(["".join([y for y in x if y is not None]) for x in map(None, *columns)])
	#return "".join(["".join(x) for x in itertools.izip_longest(*columns, fillvalue='')])
	#print "({})".format(",".join(columns))
	output_string = ""
	for i in range(0,max([len(c) for c in columns])):
		for c in columns:
			if i < len(c):
				#print c
				output_string += c[i]
	return output_string


def digraph_freqs(text):
	freqs = {}
	filtered_text = re.sub(r'[^A-Z0-9]+', '', text.upper())
	for i in range(0, len(filtered_text), 2):
		digraph = filtered_text[i:i+2]
		if digraph in freqs:
			freqs[digraph] += 1
		else:
			freqs[digraph] = 1
	return [(d, f/float(len(filtered_text))*100) for d,f in sorted(freqs.items(), key=operator.itemgetter(1))]

def digraph_ic(text):
	freqs = {}
	filtered_text = re.sub(r'[^A-Z0-9]+', '', text.upper())
	n = len(filtered_text)
	for i in range(0, len(filtered_text), 2):
		digraph = filtered_text[i:i+2]
		if digraph in freqs:
			freqs[digraph] += 1
		else:
			freqs[digraph] = 1
	return 26 * (sum([freqs[c]*(freqs[c]-1) for c in freqs]) / (n*(n-1)))
	
def digraph_decompose(text):
	characters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	mapping = {}
	ciphertext = ""
	filtered_text = re.sub(r'[^A-Z0-9]+', '', text.upper())
	for i in range(0, len(filtered_text), 2):
		digraph = filtered_text[i:i+2]
		if digraph not in mapping:
			mapping[digraph] = characters.pop(0)
		ciphertext += mapping[digraph]
	return ciphertext
	
	
def english_match_score(freqs):
	# Sort in descending order. Compare each frequency point to the test 
	# distribution and add the absolute distance. The closer it is to English,
	# the lower the differences will be.
	
	english_dist = sorted([12.702, 9.056, 8.167, 7.507, 6.966, 6.749, 6.327, 6.094, 5.987, 4.253, 4.025, 2.782, 2.758, 2.406, 2.361, 2.228, 2.015, 1.974, 1.929, 1.492, 0.978, 0.772, 0.153, 0.150, 0.095, 0.074], reverse=True)
	test_dist = sorted([f for d,f in freqs], reverse=True)
	distance = 0
	
	for e,t in zip(english_dist, test_dist):
		distance += abs(e-t)
	
	return distance
	
def index_of_coincidence(text):
	filtered_text = re.sub(r'[^A-Z0-9]+', '', text.upper())
	n = float(len(filtered_text))
	characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	return 26 * (sum([filtered_text.count(c)*(filtered_text.count(c)-1) for c in characters]) / (n*(n-1)))

def test_substitution_cipher(text, max_iterations):
	fitness = ngram_score('english_quadgrams.txt') # load our quadgram statistics
	ctext = re.sub('[^A-Z]','',text.upper())

	maxkey = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
	maxscore = -99e9
	parentscore,parentkey = maxscore,maxkey[:]
	for i in range(0,max_iterations):
		random.shuffle(parentkey)
		deciphered = SimpleSub(parentkey).decipher(ctext)
		parentscore = fitness.score(deciphered)
		count = 0
		while count < 1000:
			a = random.randint(0,25)
			b = random.randint(0,25)
			child = parentkey[:]
			# swap two characters in the child
			child[a],child[b] = child[b],child[a]
			deciphered = SimpleSub(child).decipher(ctext)
			score = fitness.score(deciphered)
			# if the child was better, replace the parent with it
			if score > parentscore:
				parentscore = score
				parentkey = child[:]
				count = 0
			count = count+1
		# keep track of best score seen so far
		if parentscore>maxscore:
			maxscore,maxkey = parentscore,parentkey[:]
	return maxscore, maxkey, SimpleSub(maxkey).decipher(ctext)
	
if __name__ == "__main__":
	sys.exit(main())
