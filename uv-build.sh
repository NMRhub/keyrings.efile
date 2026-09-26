rm -fr dist
uv build --out-dir dist . 
uv build --out-dir dist cli
twine check dist/*
if [ $? -eq 0 ]; then
	echo "upload commands:"
	echo "twine upload --verbose  --repository testpypi dist/*" 
	echo "twine upload --verbose  dist/*" 
fi
