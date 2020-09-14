# NmapToES
(First upload so be patient with me)
## Functionality
This is a pretty simple script really that allows for a few things.
1. Print your local IP address, as well as other IP addresses in the local network. (via a ping sweep and displaying responding endpoints).
2. You can also run an Nmap scan. You will be prompted an IP and a selected range. By default, nmap will run with `-oX` flag, which per Nmap's website:
> Write output in Nmap's XML format to <filename>. Normal (human readable) output will still be printed to stdout unless you ask for XML to be directed there by specifying - as <filename>. This is the preferred format for use by scripts and programs that process Nmap results.
Conveniently enough, this puts it in the JSON format we are looking for. I will add functionality to add custom options later (this is kind of just a PoC as of date).
3. Upon completing the Nmap scan, the user will be prompted if you would like to index the data into your Elasticsearch instance (Uses default :9200). User then inputs an index name (will create if it is not present) and the document will be given a document ID, beginning at "1". Upon indexing more data under the same index, document ID's will increment by a value of "1".
## Purpose / Use Case
This is more or less a small project I have been meaning to do for a little. I wanted to experiment with a few convenient python libraries (Nmap, ES, etc.) and this was a good opportunity. I hope it will bring some utility for research I do at a local University, but I would also love if someone else found use. I was thinking of maybe turning the latter functionality into a cronjob but that's all in the air. Please let me know of suggestions or ideas.

Enjoy.
