#ifndef CONFIG_H
#define CONFIG_H

namespace Configuration{

enum PROTOCOL{
	UDP,
	TCP
};

class Config{
private:
	PROTOCOL protocol_;
public:
	//  GET-SET
	PROTOCOL protocol();
	PROTOCOL protocol(PROTOCOL protocol);
};

} // namespace Configuration

#endif
