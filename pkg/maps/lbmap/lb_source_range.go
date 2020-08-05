// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	SourceRange4MapName = "cilium_lb4_source_range"
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SourceRangeKey4 struct {
	PrefixLen uint32
	Address   types.IPv4
	RevNATID  uint16
}

func (k *SourceRangeKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *SourceRangeKey4) NewValue() bpf.MapValue    { return &SourceRangeValue{} }
func (k *SourceRangeKey4) String() string            { return fmt.Sprintf("%s", k.Address) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SourceRangeValue struct {
	Pad uint8 // not used
}

func (v *SourceRangeValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SourceRangeValue) String() string              { return "" }

var SourceRange4Map = bpf.NewMap(
	SourceRange4MapName,
	bpf.MapTypeLPMTrie,
	&SourceRangeKey4{}, int(unsafe.Sizeof(SourceRangeKey4{})),
	&SourceRangeValue{}, int(unsafe.Sizeof(SourceRangeValue{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

type SourceRangeBPFMap struct{}

func (*SourceRangeBPFMap) Update(cidr net.IPNet, revNATID uint16) error {
	return SourceRange4Map.Update(key4(cidr, revNATID), &SourceRangeValue{})
}

func (*SourceRangeBPFMap) Delete(cidr net.IPNet, revNATID uint16) error {
	return SourceRange4Map.Delete(key4(cidr, revNATID))
}

//func (*IPMasqBPFMap) Dump() ([]net.IPNet, error) {
//	cidrs := []net.IPNet{}
//	if err := IPMasq4Map.DumpWithCallback(
//		func(key bpf.MapKey, value bpf.MapValue) {
//			cidrs = append(cidrs, keyToIPNet(key.(*Key4)))
//		}); err != nil {
//		return nil, err
//	}
//	return cidrs, nil
//}

func key4(cidr net.IPNet, revNATID uint16) *SourceRangeKey4 {
	ones, _ := cidr.Mask.Size()
	key := &SourceRangeKey4{PrefixLen: uint32(ones), RevNATID: revNATID}
	copy(key.Address[:], cidr.IP.To4())
	return key
}

//func keyToIPNet(key *Key4) net.IPNet {
//	var (
//		cidr net.IPNet
//		ip   types.IPv4
//	)
//
//	cidr.Mask = net.CIDRMask(int(key.PrefixLen), 32)
//	key.Address.DeepCopyInto(&ip)
//	cidr.IP = ip.IP()
//
//	return cidr
//}
