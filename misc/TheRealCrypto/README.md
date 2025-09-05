# The Real Crypto Master [_snakeCTF 2025 Quals_]

**Category**: misc/osint
**Author**: mrBymax

## Description

It's common sense that "crypto" stands for "cryptocurrency".
With my masterclass, you will learn everything you need to be like me!

You only need to find me :-D

### Hints

None.

## Solution

Here is a possible solution to this challenge.

### First step: understanding the situation

A file containing some expenses is received. After a thorough review of the expenses.csv metadata (through the .DS_Store), the subject is identified: @bepifrico. This looks like a username.

### Second step: finding @bepifrico online

Using a manual search or an automated tool, Bepi's X profile can be found [here](https://x.com/bepifrico).

### Third step: retrieving the first part of the flag

In a recent post, it is said that Bepi wanted to to the usual stream, but X set streams a premium feature and he switched the streaming on YouTube.
A link to his YouTube Channel is found. Bepi's profile is transmitting a live recording: [this](./attachments/streaming_audio.wav).
The message states the fist part of the flag and tells that the second part is easy to find with "the right amount of geoguessing and a great amount of nerd culture".
The only _geoguessable_ post is the most recent. Looking for the image on Google Images, it's discovered the name of the artist: **aldam**

### Fourth step: retrieve the second part of the flag

Looking at aldam's Instagram profile, the right location is found: "Multicinema Modernissimo" in Naples, Italy.
From bepi's profile, some more hints are given: on the 30th day of July, he was waiting to go to that cinema, surely to watch a film that "starts in two hours" and regards a superhero.

In July 2025, two films revolved around superheros stories: "The Fantastic 4: First Steps" and James Gunn's "Superman" so an intuition could be made.

To prove the intuition it is possible to check on the cinema page if there's a show that starts in two hours and two minutes (as stated in the second post of the thread) from 17:13 CEST (the timezone is given by the position and the day of the year).

A snapshot of Multicinema's ticket page is available on Wayback Machine [here](https://web.archive.org/web/20250730152622/https://modernissimo.andromeda.andromedacinemas.it/)

From there it's possible to know that the film bepi has watched is "I Fantastici 4: Gli Inizi".

From bepi's profile it's easy to see that he also wanted to write a review, so another step is necessary. The main free movie review portal is Letterboxd, so it's a good starting point. (Please note that if you tried an automated scan in the first step you've probably already found this profile).

From bepi's Letterboxd profile [here](https://letterboxd.com/bepifrico/) it's possible to retrieve the last part of the flag.
