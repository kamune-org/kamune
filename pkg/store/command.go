package store

func (c *Command) AddPlain(key, value []byte) error {
	bucket := c.tx.Bucket(bucketName)
	return bucket.Put(key, value)
}

func (c *Command) AddEncrypted(key, value []byte) error {
	return c.AddPlain(key, c.store.cipher.Encrypt(value))
}
