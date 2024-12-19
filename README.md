# zkSC-opensource

A prototype implementation for the zero knowledge access, key agreement and handover protocol for satellite commuication proposed in paper 
<font color=Blue>"Fine-grained Anonymous Access for Satellite
Communication using Zero Knowledge Proof"</font>

To run the code (rust/cargo must be installed):
```
cd ZKSC-OPENSOURCE
./runscripts/actest.sh
```
or
```
./runscripts/hotest.sh
```
The end to end simulation latency will be written to .csv files in the ```zkcreds-rs``` folder.
