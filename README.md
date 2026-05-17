# TB File Browser
Forked from [cosmic-files](https://github.com/pop-os/cosmic-files.git)


For now, SSH connections must be configured using a private and public key pair (password authentication is not supported).



## References
IMM:  
[Mycobacteroides abscessus subsp. bolletii BD, whole genome shotgun sequencing project](https://www.ncbi.nlm.nih.gov/nucleotide/AHAS00000000)  
  
hsp65:  
[Web-accessible database of hsp65 sequences from Mycobacterium reference strains.](https://europepmc.org/article/pmc/pmc3122750)  

  
Jody Phelan:  
[TBProfiler](https://github.com/jodyphelan/TBProfiler)  
[tbdb](https://github.com/jodyphelan/tbdb)  (used by TBProfiler by default)  
[ntm-db](https://github.com/pathogen-profiler/ntm-db)  (for abscessus_resistance_variants.csv)  

tbdb:  
[Catalogue of mutations in Mycobacterium tuberculosis complex and their association with drug resistance, 2nd ed](https://www.who.int/publications/i/item/9789240082410)  
  
ntm-db:  
[Clinical Whole Genome Sequencing for Clarithromycin and Amikacin Resistance Prediction and Subspecies Identification of Mycobacterium abscessus](https://www.jmdjournal.org/article/S1525-1578(21)00259-2/fulltext)  
[Global phylogenomic analyses of Mycobacterium abscessus provide context for non cystic fibrosis infections and the evolution of antibiotic resistance](https://www.nature.com/articles/s41467-021-25484-9)  
[Multidrug tolerance conferred by loss-of-function mutations in anti-sigma factor RshA of Mycobacterium abscessus](https://journals.asm.org/doi/10.1128/aac.01051-24)  


## Doc

### NTM 

rrl M. abscessus macrolides:  

<pre>
impl RrlSnpCall {
    pub fn call_tag(&self) -> String {
        match self.query_base {
            None => "NA".to_string(),
            Some(b) if b == self.wt_base => format!("{} (wt)", self.wt_base as char),
            Some(b) if self.resistance_bases.contains_key(&b) => {
                let drugs = self.resistance_bases[&b].join(", ");
                format!("{} ({})", b as char, drugs)
            }
            Some(b) => format!("{} (mutation)", b as char),
        }
    }
}
</pre>
  
### Generation of species identification databases:  

[The INSD Collaboration (GenBank/ENA/DDBJ) source feature qualifier ‘type_material’ ](https://pmc.ncbi.nlm.nih.gov/articles/PMC4383940/):  
Type material is the taxonomic device that ties formal names to the physical specimens that serve as exemplars for the species.  
For the prokaryotes these are strains submitted to the culture collections;  
for the eukaryotes they are specimens submitted to museums or herbaria.  
The NCBI Taxonomy Database (http://www.ncbi.nlm.nih.gov/taxonomy) now includes annotation of type material that we use to flag sequences from type in GenBank and in Genomes.  
  
<ins>myco_rrs.fasta:</ins>   
Mycobacteriaceae[Organism] AND (16S[Title] OR rrs[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]        
<ins>myco_hsp65.fasta:</ins>   
Mycobacteriaceae[Organism] AND (hsp65[Gene Name] OR groEL2[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]  
<ins>myco_rpoB.fasta:</ins>   
Mycobacteriaceae[Organism] AND rpoB[Gene Name] AND 400:3000[SLEN] AND type_material[Filter]  
<ins>myco_erm41.fasta:</ins>   
Mycobacteriaceae[Organism] AND erm(41)[Gene Name] AND 400:3000[SLEN]  
<ins>myco_rrl.fasta:</ins>   
Mycobacteriaceae[Organism] AND (23S ribosomal RNA[Title] OR rrl[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]  
   
  
### TBProfiler:
  
Unique confidence values of TBProfiler (examples/tbgetconfidencetypes.rs):
  - Assoc w R
  - Assoc w R - Interim
  - Not assoc w R
  - Not assoc w R - Interim
  - Uncertain significance  

<pre>
fn confidence_rank(conf: &str) -> u8 {  
    match conf {  
        "Assoc w R" => 0,  
        "Assoc w R - Interim" => 1,  
        "Uncertain significance" => 2,  
        "Not assoc w R - Interim" => 3,  
        "Not assoc w R" => 4,  
        _ => 5, // unknown / fallback  
    }  
}  
  
fn is_susceptible: rank >= 2
</pre>

[Dateien](https://uzh-my.sharepoint.com/:f:/g/personal/mmeuli_imm_uzh_ch/IgANQxBmjwxaTpjCTdDPgocxAdiRcxx5qaYzsTE9Twfyx8k?e=OrNlms)


### Dev
On branch tbprofiler run on Windows with:
$env:RUST_LOG="info"; cargo run



