// get_vcek.go
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/coserv"
)

// ----- JSON Helper Types -----

// This struct models the API response from a call to the RIM service
type RimServiceResponse struct {
	Id          string `json:"id"`
	Rim         string `json:"rim"`
	Sha256      string `json:"sha256"`
	LastUpdated string `json:"last_updated"`
	RimFormat   string `json:"rim_format"`
	RequestId   string `json:"request_id"`
}

// ----- Main program -----

func main() {
	// Command-line flags.
	rimid := flag.String("rimid", "", "RIM identifier")
	flag.Parse()

	if *rimid == "" {
		fmt.Printf("Usage: %s -rimid=<rim_identifier>\n", os.Args[0])
		os.Exit(1)
	}

	// Construct NVIDIA RIM service URL for query
	urlStr := fmt.Sprintf("https://rim.attestation.nvidia.com/v1/rim/%s", *rimid)
	log.Printf("Requesting RIM file from: %s", urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		log.Fatalf("HTTP GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Error response from NVIDIA RIM service: %d %s\nResponse body: %s", resp.StatusCode, resp.Status, string(body))
		os.Exit(1)
	}

	// Read the successful response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Reading response error: %v", err)
		os.Exit(1)
	}
	log.Printf("Received successful response from NVIDIA RIM service (%d bytes)", len(body))

	var rimServiceResponse RimServiceResponse
	json.Unmarshal(body, &rimServiceResponse)

	if rimServiceResponse.RimFormat != "CORIM" {
		log.Fatalf("Expected RIM to be formatted as CORIM, but the actual format is %s", rimServiceResponse.RimFormat)
	}

	corimBytes, err := base64.StdEncoding.DecodeString(rimServiceResponse.Rim)

	if err != nil {
		log.Fatalf("Failed to base64 decode the RIM byte string %s", rimServiceResponse.Rim)
		os.Exit(1)
	}

	log.Printf("Decoded %d bytes of CoRIM data.", len(corimBytes))

	var scorim corim.SignedCorim
	err = scorim.FromCOSE(corimBytes)
	if err != nil {
		log.Fatalf("Failed to parse COSE: %v", err)
		os.Exit(1)
	}

	// Begin with an empty result set
	coservResult := *coserv.NewResultSet()

	// Start mapping data out of the CoRIM and into the CoSERV result set.
	for _, t := range scorim.UnsignedCorim.Tags {
		cborTag, cborData := t[:3], t[3:]

		// We'll just look at CoMID tags
		if bytes.Equal(cborTag, corim.ComidTag) {
			log.Printf("Found a CoMID tag.")
			var c comid.Comid
			err = c.FromCBOR(cborData)

			if err != nil {
				log.Fatalf("Failed to populate CoMID from CBOR: %v", err)
				os.Exit(1)
			}

			// We'll just look at reference value triples in the CoMID
			for _, triple := range c.Triples.ReferenceValues.Values {
				// Directly transplant each RV triple into the result
				log.Printf("Adding a reference value triple to the result.")
				coservResult.AddReferenceValues(triple)
			}
		}
	}
}
