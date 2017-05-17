//Carga de dependencias
const fs = require('fs');
const download = require('download');
const decompress = require('decompress');
//var https   = require('https');
var unzip = require('unzip');

//Definicion de variables
var url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip";
//Inicio descarga de archivo
/*
download(url, 'vulns').then(() => {
    console.log('Descarga OK');
});
//download(url).pipe(fs.createWriteStream('./vulns/cve.zip'));

//Descomprime archio
fs.createReadStream('./vulns/cve.zip').pipe(unzip.Extract({ path: './vulns' }));
*/

var json1 = JSON.parse(fs.readFileSync('cve.json', 'utf8'));
var array = JSON.stringify(json1.CVE_Items);

for(var item of json1.CVE_Items) {
     //console.log('item: ', JSON.stringify(item));
     if( typeof item.CVE_impact.CVE_impact_cvssv3.bm !== 'undefined' ){
     	if (item.CVE_impact.CVE_impact_cvssv3.bm.score > 4){
     		console.log('Riesgo:', JSON.stringify(item.CVE_impact.CVE_impact_cvssv3.bm.score));
     	}     	
     }     
  }
/*
for(var exKey in obj) {
      console.log("key:"+exKey+", value:"+exjson[exKey]);
 }
 
 

console.log(obj);
*/
/*
//Cargo archivo de json a variable, cargar solamente array que nos interesa: CVE_Items
//Para cada objeto del array solamente dejar los de riesgo CVSSv3 mayores a 4  //CVE_impact > CVE_impact_cvssv3 > score

//Hacer un grep de sistemas y aplicaciones (habra que seleccionar a que cliente corresponde el boletin para saber que lista de aplicaciones tomar)

//Variable json con resultados finales para mostrar en tabla html
/******************************
Pseudocodigo: Descargar json desde https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip
Descomprimir
Filtrar solo los de riesgo cvss mayor a 4 - CVE_impact - CVE_impact_cvssv3 - score
Filtrar los del último mes - CVE_references - CVE_reference_data(0) - publish_date
Filtrar los que podrian impactar en sistemas del cliente
Mostrar resultados en tabla html

Agregar aplicaciones a la chdm !
Rodrigo va a tomar lista de aplicaciones utilizadas en Sistar para luego hacer grep contra la lista de vulnerabilidades.
*******************************/