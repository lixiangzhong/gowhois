//https://help.aliyun.com/knowledge_detail/35772.html
package gowhois

import (
	"fmt"
	"reflect"
	"strings"
)

type WhoisInfo struct {
	DomainName     string        `whois:"Domain Name"`
	DomainID       string        `whois:"Domain ID"`
	NameServer     []string      `whois:"Name Server,nserver"`
	UpdatedDate    string        `whois:"Updated Date,Update Date"`
	CreationDate   string        `whois:"Registration Time,Creation Date"`
	ExpirationDate string        `whois:"Expiration Date,Expiration Time,Expiry Date"`
	Status         []string      `whois:"Domain Status,state"`
	Registrar      RegistrarInfo //注册商
	Registrant     Info          `whois:"Registrant"` //注册者
	Administrative Info          `whois:"Admin"`      //管理联系人
	Technical      Info          `whois:"Tech"`       //技术联系人
	Billing        Info          `whois:"Billing"`    //付费联系人
	DNSSEC         string        `whois:"DNSSEC"`
}

//注册商
type RegistrarInfo struct {
	WhoisServer string `whois:"WHOIS Server,Whois Server"`
	URL         string `whois:"Registrar URL,Referral URL"`
	Name        string `whois:"Registrar,registrar"`
	ID          string `whois:"Registrar IANA ID"`
	Email       string `whois:"Registrar Abuse Contact Email"`
	Phone       string `whois:"Registrar Abuse Contact Phone"`
}

type Info struct {
	ID           string `whois:"ID"`
	Name         string `whois:",Name"`
	Organization string `whois:"Organization"`
	Street       string `whois:"Street"`
	City         string `whois:"City"`
	Province     string `whois:"State/Province"`
	PostalCode   string `whois:"Postal Code"`
	Country      string `whois:"Country"`
	Phone        string `whois:"Phone"`
	PhoneExt     string `whois:"Phone Ext"`
	Fax          string `whois:"Fax"`
	FaxExt       string `whois:"Fax Ext"`
	Email        string `whois:"Email,Contact Email"`
}

func PrintTags() {
	w := new(WhoisInfo)
	v := reflect.ValueOf(w).Elem()
	t := v.Type()
	for index := 0; index < v.NumField(); index++ {
		vField := v.Field(index)
		tags := strings.Split(t.Field(index).Tag.Get("whois"), ",")
		// name := t.Field(index).Name
		kind := vField.Kind()
		if kind == reflect.Struct {
			Struct := vField
			tStruct := Struct.Type()
			for i := 0; i < Struct.NumField(); i++ {
				// field := Struct.Field(i)
				_tags := strings.Split(tStruct.Field(i).Tag.Get("whois"), ",")
				for _, tag := range tags {
					for _, _tag := range _tags {
						if tag != "" {
							fmt.Println(tag + " " + _tag)
						} else {
							fmt.Println(_tag)
						}

					}
				}
			}
		} else if kind == reflect.Slice {
			for _, tag := range tags {
				fmt.Println(tag)
			}
		} else {
			for _, tag := range tags {
				fmt.Println(tag)
			}
		}
	}
}
func Parse(result string) *WhoisInfo {
	w := new(WhoisInfo)
	v := reflect.ValueOf(w).Elem()
	t := v.Type()
	for index := 0; index < v.NumField(); index++ {
		vField := v.Field(index)
		tags := strings.Split(t.Field(index).Tag.Get("whois"), ",")
		kind := vField.Kind()
		if kind == reflect.Struct {
			Struct := vField
			tStruct := Struct.Type()

			for i := 0; i < Struct.NumField(); i++ {
				_tags := strings.Split(tStruct.Field(i).Tag.Get("whois"), ",")
			NextField:
				for _, tag := range tags {
					for _, _tag := range _tags {
						if tag != "" {
							// fmt.Println(tag + " " + _tag)
							if value, ok := getValue(result, tag+" "+_tag); ok {
								Struct.Field(i).SetString(value)
								break NextField
							}
						} else {
							// fmt.Println(_tag)
							if value, ok := getValue(result, _tag); ok {
								Struct.Field(i).SetString(value)
								break NextField
							}
						}
					}
				}
			}
		} else if kind == reflect.Slice {
			for _, tag := range tags {
				if value, ok := getValueSlice(result, tag); ok {
					vField.Set(reflect.ValueOf(value))
					break
				}
			}
		} else {
			for _, tag := range tags {
				if value, ok := getValue(result, tag); ok {
					vField.SetString(value)
					break
				}
			}
		}
	}
	return w
}

func getValue(result, tag string) (string, bool) {
	key := strings.TrimSpace(tag) + ":"
	start := strings.Index(result, key)
	if start < 0 {
		return "", false
	}
	start += len(key)
	end := strings.Index(result[start:], "\n")
	value := strings.TrimSpace(result[start : start+end])
	return value, true
}

func getValueSlice(result, tag string) (slice []string, ok bool) {
	key := tag + ":"
	for {
		start := strings.Index(result, key)
		if start < 0 {
			break
		}
		ok = true
		start += len(key)
		end := strings.Index(result[start:], "\n")
		value := strings.TrimSpace(result[start : start+end])
		slice = append(slice, value)
		result = result[start+end:]
	}
	return
}
