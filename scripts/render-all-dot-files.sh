for dot_file in $(find . -name '*.dot'); do
    png_file=$(echo $dot_file | sed 's/.dot/.png/')
    echo "Converting $dot_file to $png_file"
    dot -Tpng -Gdpi=300 $dot_file -o $png_file
done
