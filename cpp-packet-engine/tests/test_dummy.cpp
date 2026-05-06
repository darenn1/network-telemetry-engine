#include <gtest/gtest.h>
 
TEST(DummyTest, HarnessWorks) {
    EXPECT_EQ(1 + 1, 2);
}
 
TEST(DummyTest, StringComparison) {
    std::string engine = "packet-engine";
    EXPECT_EQ(engine, "packet-engine");
}
 