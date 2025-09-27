import geoip2.database

def get_geo_info(ip_address, db_path='GeoLite2-City.mmdb'):
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip_address)
            geo_info = {
                'ip': ip_address,
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
            return geo_info
    except Exception as e:
        return {'error': str(e)}

if __name__ == "__main__":
    ip = input("Enter IP address: ")
    result = get_geo_info(ip)
    print(result)