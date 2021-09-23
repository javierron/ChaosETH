const fs = require('fs')
const data = require('./query_results.json')

const metrics = data.other_metrics;

handleErr = err => {
    if(err){
       console.log('error while writing:' , err);
    }
}

var headers = "timestamp"
var dict = {}

metrics.forEach(element => {
    headers = `${headers},${element.metric_name}` ;
    element.data_points.forEach(dp => {
        dict[dp[0]] = dict[dp[0]] == undefined ? `${dp[1]}` : `${dict[dp[0]]},${dp[1]}`;       
    });
}); 

fs.appendFile('parsed.csv', `${headers}\n`, handleErr);

Object.keys(dict).forEach( key => {
    fs.appendFile('parsed.csv', `${key},${dict[key]}\n`, handleErr)
})


