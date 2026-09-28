package cluster

import secretspkg "github.com/aerol-ai/microvm/pkg/secrets"

func testSecretRef(sandboxID, incarnationID string) string {
	return secretspkg.FormatRef(sandboxID, incarnationID, secretspkg.RefVersion)
}

func testPlacementSecrets(sandboxID, incarnationID string, generation int64) PlacementSecrets {
	return PlacementSecrets{
		Ref:            testSecretRef(sandboxID, incarnationID),
		Version:        secretspkg.RefVersion,
		IncarnationID:  incarnationID,
		SealGeneration: generation,
	}
}
