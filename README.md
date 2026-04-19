# CRAB - Cli Response Action Buddy:
## A Rust-based command line tool for Incident Response.
---
### DISCLAIMER:
This tool is very much still work in progress and is being worked on by me, Condor. Currently, the features available are limited to just IP report grabs from virustotal.
However, the features that will eventually ship are:

* IP, Hash, Domain, and Url lookups from virustotal
* IP enrichment from DB-IP, or IpInfo, or both.
* Domain enrichement from whois or other whois-like apis.
* Hash enrichment from hybrid-analysis or other apis.
* Url lookups from urlscan.
* Multi-lookups via CSV's

All that to say, the project has a long way to go, and this is selfishly my way of teaching myself Rust. It won't be *idiomatic* or *optimized* out the gate, but my plan is to get it there. Okay! Rant over; let's get into the purpose. 

### What's CRAB?
CRAB is a simple, easy to configure, drop in tool that will perform enrichment on an IOC (that's 'indicator of compromise' to the uninitiated), from multiple sources and it will spit out all of the information it can, depending on what API keys you feed your crab. Command line IOC enrichment in a *pinch!*

### Why CRAB?
Well, simply put, Rust's mascot is a crab. I wrote this in Rust. The acronym was funny but reasonable, so it stuck!

### How's CRAB?
CRAB's fine! Thanks for asking!

---
### Getting Started
For now, until I have a more stable version, if you want to toy around with the app you will need to clone and build it. Fortunately, Rust's Cargo tool makes it very easy to do so.
Once you have Cargo installed:
* Clone this repo.
* `cd` into the repo
* run `cargo build` 
	* *Note: cargo will likely yell at you for my transgressions. As long as the build succeeds, you should be able to toy around with the binary*
* That's it! The binary will be located in `target/debug/` directory.

### Running CRAB
As stated in the disclaimer section, the only portion that is set to work start-to-finish is the IP enrichment for VirusTotal part. 

**Before you run** make sure you have a crab.toml file in the same directory as CRAB. For now the format should be like this:

```TOML
[keys]
virustotal = "[your_key_here]"

[apis]
virustotal = true
```

After this, you should be all set to run CRAB!
Try something like:
```bash
./crab enrich ip 8.8.8.8
```
