package aqualightning

import (
	"fmt"
	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	WebhookTimeout int32 = 5
)

// EnforcerParameters :
type LightningParameters struct {
	Lightning *v1alpha1.AquaLightning
}

// AquaEnforcerHelper :
type AquaLightningHelper struct {
	Parameters LightningParameters
}

func newAquaLightningHelper(cr *v1alpha1.AquaLightning) *AquaLightningHelper {
	params := LightningParameters{
		Lightning: cr,
	}

	return &AquaLightningHelper{
		Parameters: params,
	}
}

func (lightning *AquaLightningHelper) newAquaKubeEnforcer(cr *v1alpha1.AquaLightning) *v1alpha1.AquaKubeEnforcer {
	registry := consts.Registry
	if cr.Spec.KubeEnforcer.RegistryData != nil {
		if len(cr.Spec.KubeEnforcer.RegistryData.URL) > 0 {
			registry = cr.Spec.KubeEnforcer.RegistryData.URL
		}
	}
	tag := consts.LatestVersion
	if cr.Spec.KubeEnforcer.Infrastructure.Version != "" {
		tag = cr.Spec.KubeEnforcer.Infrastructure.Version
	}

	labels := map[string]string{
		"app":                cr.Name + "-lightning",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"aqua.component":     "kubeenforcer",
	}
	annotations := map[string]string{
		"description": "Deploy Aqua KubeEnforcer",
	}

	AquaStarboardDetails := v1alpha1.AquaStarboardDetails{
		AllowAnyVersion: true,
		Infrastructure: &v1alpha1.AquaInfrastructure{
			Version:        consts.StarboardVersion,
			ServiceAccount: "starboard-operator",
		},
		Config: v1alpha1.AquaStarboardConfig{
			ImagePullSecret: "starboard-registry",
		},
		StarboardService: &v1alpha1.AquaService{
			Replicas: 1,
			ImageData: &v1alpha1.AquaImage{
				Registry:   "docker.io/aquasec",
				Repository: "starboard-operator",
				PullPolicy: "IfNotPresent",
			},
		},
	}
	aquaKubeEnf := &v1alpha1.AquaKubeEnforcer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaKubeEnforcer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: v1alpha1.AquaKubeEnforcerSpec{
			Config: v1alpha1.AquaKubeEnforcerConfig{
				GatewayAddress:  fmt.Sprintf("%s.%s:8443", fmt.Sprintf(consts.GatewayServiceName, cr.Name), cr.Namespace),
				ClusterName:     "Default-cluster-name",
				ImagePullSecret: cr.Spec.Common.ImagePullSecret,
			},
			Token:                  consts.DefaultKubeEnforcerToken,
			EnforcerUpdateApproved: cr.Spec.KubeEnforcer.EnforcerUpdateApproved,
			AllowAnyVersion:        cr.Spec.KubeEnforcer.AllowAnyVersion,
			ImageData: &v1alpha1.AquaImage{
				Registry:   registry,
				Repository: "kube-enforcer",
				Tag:        tag,
				PullPolicy: "Always",
			},

			KubeEnforcerService: &v1alpha1.AquaService{
				Resources: cr.Spec.KubeEnforcer.KubeEnforcerService.Resources,
			},

			DeployStarboard: &AquaStarboardDetails,
		},
	}

	return aquaKubeEnf
}

func (lightning *AquaLightningHelper) newAquaEnforcer(cr *v1alpha1.AquaLightning) *v1alpha1.AquaEnforcer {
	registry := consts.Registry
	if cr.Spec.Enforcer.EnforcerService.ImageData != nil {
		if len(cr.Spec.Enforcer.EnforcerService.ImageData.Registry) > 0 {
			registry = cr.Spec.Enforcer.EnforcerService.ImageData.Registry
		}
	}

	labels := map[string]string{
		"app":                cr.Name + "-enforcer",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"aqua.component":     "enforcer",
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Enforcer",
	}
	aquaenf := &v1alpha1.AquaEnforcer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaEnforcer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: v1alpha1.AquaEnforcerSpec{
			Infrastructure: cr.Spec.Enforcer.Infrastructure,
			Common:         cr.Spec.Common,
			Gateway: &v1alpha1.AquaGatewayInformation{
				Host: fmt.Sprintf("%s-gateway", cr.Name),
				Port: 8443,
			},
			Token: cr.Spec.Enforcer.Token,
			Secret: &v1alpha1.AquaSecret{
				Name: fmt.Sprintf("%s-enforcer-token", cr.Name),
				Key:  "token",
			},
			EnforcerService: &v1alpha1.AquaService{
				ImageData: &v1alpha1.AquaImage{
					Registry: registry,
				},
				Resources: cr.Spec.Enforcer.EnforcerService.Resources,
			},
			RunAsNonRoot:           cr.Spec.Enforcer.RunAsNonRoot,
			EnforcerUpdateApproved: cr.Spec.Enforcer.EnforcerUpdateApproved,
		},
	}

	return aquaenf
}
