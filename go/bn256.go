package main
 
import (
    gonode "github.com/jgranstrom/gonodepkg"
    json "github.com/jgranstrom/go-simplejson"
)
 
func main() {	
    gonode.Start(process)
}
 
func process(cmd *json.Json) (response *json.Json) {
    response, m, _ := json.MakeMap()
 
    if(cmd.Get("command").MustString() == "Hello there...") {
        m["response"] = "General Kenobi."
    } else {
        m["response"] = "What?"
    }
 
    return
}