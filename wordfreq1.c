// ECE 2524 SP14
// Written by Hyun Moon (hyunmoon)
// This is Part 1 of wordfreq assignment

#include <stdio.h>
#include <stdlib.h>
#include <analytics.h>

void some_callback(const char* word, int count);

int main() {
	if (stdin == NULL)
	{
		fprintf(stderr, "Error: Unable to read from file\n");
		exit(1);
	}

	int nlimit = 10;
	word_list_t wl;
	wl = word_list_create(nlimit);
	
	word_map_t wm;
	wm = word_map_create(nlimit);

	wl = split_words(stdin);
	wm = count_words(wl);
	sort_counted_words(wm, 0);

	word_map_nforeach(wm, some_callback, nlimit);

	// word_list_free(wl);
	// word_map_free(wm);

	return 0;
}

void some_callback(const char* word, int count)
{
	printf("%d %s\n", count, word);
}
